#!/usr/bin/env python3
"""
sniff_all.py
Logs ALL traffic. Optional filters via command line.
Usage:
  python3 sniff_all.py                    # all traffic, all interfaces
  python3 sniff_all.py -i eth0            # specific interface
  python3 sniff_all.py -p 10443           # specific port
  python3 sniff_all.py -i lo -p 8080      # combined
  python3 sniff_all.py --no-payload       # headers only, no body
  python3 sniff_all.py --keywords-only    # back to filtered mode
"""

import socket, struct, re, os, sys, argparse
from datetime import datetime

# ── Args ──────────────────────────────────────────────────
parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface",
                    default="any",
                    help="Interface (eth0/lo/any)")
parser.add_argument("-p", "--port",
                    type=int, default=None,
                    help="Filter by port")
parser.add_argument("--no-payload",
                    action="store_true",
                    help="Skip payload, headers only")
parser.add_argument("--keywords-only",
                    action="store_true",
                    help="Only log interesting lines")
parser.add_argument("-o", "--output",
                    default=None,
                    help="Output file (default: auto)")
args = parser.parse_args()

INTERFACE     = args.interface
FILTER_PORT   = args.port
NO_PAYLOAD    = args.no_payload
KEYWORDS_ONLY = args.keywords_only
OUTFILE       = args.output or \
    f"sniff_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

INTERFACES = (
    ["lo", "eth0", "tunl0"]
    if INTERFACE == "any"
    else [INTERFACE]
)

PORT_LABELS = {
    10443: "Jupyter-TLS",  8080: "VSCode/API",
    8081:  "Jupyter",      8200: "Vault",
    8443:  "oauth2-proxy", 443:  "HTTPS",
    5432:  "PostgreSQL",   27017:"MongoDB",
    6379:  "Redis",        9090: "Prometheus",
    6443:  "k8s-API",      2379: "etcd",
    53:    "DNS",          9000: "MinIO",
    80:    "HTTP",         8888: "Jupyter-int",
    10250: "Kubelet",
}

KEYWORDS = [
    "authorization", "bearer", "token", "cookie",
    "password", "secret", "vault", "oauth", "key",
    "access_key", "api_key", "credential",
]

# ── Helpers ───────────────────────────────────────────────

def port_label(p):
    return f"{p}({PORT_LABELS[p]})" \
           if p in PORT_LABELS else str(p)

def is_interesting(text):
    tl = text.lower()
    return any(kw in tl for kw in KEYWORDS)

def fmt_payload(payload, max_bytes=2048):
    """Format raw payload — show both hex and text"""
    try:
        text = payload.decode("utf-8", errors="replace")
        # Clean up non-printable except newlines/tabs
        clean = re.sub(r'[^\x09\x0a\x0d\x20-\x7e]',
                       '.', text)
        return clean[:max_bytes]
    except:
        # Hex dump for binary
        hex_str = payload[:256].hex()
        return ' '.join(hex_str[i:i+2]
                       for i in range(0, len(hex_str), 2))

def open_sockets(interfaces):
    socks = {}
    for iface in interfaces:
        try:
            s = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.htons(0x0003)
            )
            s.bind((iface, 0))
            s.settimeout(0.05)
            socks[iface] = s
            print(f"  ✓ Opened {iface}")
        except Exception as e:
            print(f"  ✗ Cannot open {iface}: {e}")
    return socks

# ── Packet handler ────────────────────────────────────────

def handle_packet(raw, iface, f, stats):
    stats["total"] += 1

    # ── Ethernet ──────────────────────────────────────────
    if len(raw) < 14:
        return
    eth_type = struct.unpack("!H", raw[12:14])[0]

    # Handle both with and without ethernet header
    if eth_type == 0x0800:
        ip_data = raw[14:]
    elif eth_type == 0x86DD:
        # IPv6 — log minimally
        write(f, f"[IPv6] iface={iface} "
                 f"len={len(raw)}")
        return
    else:
        ip_data = raw  # assume raw IP

    if len(ip_data) < 20:
        return

    # ── IP ────────────────────────────────────────────────
    iph   = struct.unpack("!BBHHHBBH4s4s", ip_data[:20])
    proto = iph[6]
    src   = socket.inet_ntoa(iph[8])
    dst   = socket.inet_ntoa(iph[9])
    ihl   = (iph[0] & 0xF) * 4
    ttl   = iph[5]
    total_len = iph[2]
    rest  = ip_data[ihl:]

    # ── TCP ───────────────────────────────────────────────
    if proto == 6:
        if len(rest) < 20:
            return
        tcph   = struct.unpack("!HHLLBBHHH", rest[:20])
        sport  = tcph[0]
        dport  = tcph[1]
        seq    = tcph[2]
        ack    = tcph[3]
        flags  = tcph[5]
        win    = tcph[6]
        offset = (tcph[4] >> 4) * 4
        payload = rest[offset:]

        # Decode flags
        flag_str = "".join([
            "S" if flags & 0x02 else "",
            "A" if flags & 0x10 else "",
            "F" if flags & 0x01 else "",
            "R" if flags & 0x04 else "",
            "P" if flags & 0x08 else "",
        ]) or "."

        # Port filter
        if FILTER_PORT and \
           sport != FILTER_PORT and \
           dport != FILTER_PORT:
            return

        stats["tcp"] += 1

        # Build header line
        sl = port_label(sport)
        dl = port_label(dport)
        header = (
            f"TCP  {iface:5} "
            f"{src:15}:{sl:20} → "
            f"{dst:15}:{dl:20} "
            f"flags={flag_str:4} "
            f"seq={seq} "
            f"len={len(payload)}"
        )

        # Payload text
        payload_text = ""
        if payload and not NO_PAYLOAD:
            ptext = fmt_payload(payload)
            if ptext.strip():
                payload_text = ptext

        # Decide whether to log
        if KEYWORDS_ONLY:
            if not is_interesting(
                payload_text + header
            ):
                return

        # Write
        write(f, "─" * 80)
        write(f, header)

        if payload_text:
            # Split into lines for readability
            lines = payload_text.splitlines()
            for line in lines:
                if line.strip():
                    write(f, f"  | {line}")

            # Highlight interesting lines
            for line in lines:
                if is_interesting(line):
                    write(f,
                          f"  *** {line.strip()[:150]}")
                    stats["hits"] += 1

        stats["logged"] += 1

    # ── UDP ───────────────────────────────────────────────
    elif proto == 17:
        if len(rest) < 8:
            return
        sport, dport = struct.unpack("!HH", rest[:2])
        payload = rest[8:]

        if FILTER_PORT and \
           sport != FILTER_PORT and \
           dport != FILTER_PORT:
            return

        stats["udp"] += 1

        sl = port_label(sport)
        dl = port_label(dport)

        write(f, "─" * 80)
        write(f, (
            f"UDP  {iface:5} "
            f"{src:15}:{sl:20} → "
            f"{dst:15}:{dl:20} "
            f"len={len(payload)}"
        ))

        if payload and not NO_PAYLOAD:
            ptext = fmt_payload(payload)
            if ptext.strip():
                for line in ptext.splitlines():
                    if line.strip():
                        write(f, f"  | {line}")

        stats["logged"] += 1

    # ── ICMP ──────────────────────────────────────────────
    elif proto == 1:
        if len(rest) < 4:
            return
        icmp_type, icmp_code = rest[0], rest[1]
        write(f, (
            f"ICMP {iface:5} "
            f"{src:15} → {dst:15} "
            f"type={icmp_type} code={icmp_code}"
        ))
        stats["logged"] += 1

    # ── Other ─────────────────────────────────────────────
    else:
        write(f, (
            f"IP   {iface:5} "
            f"{src} → {dst} "
            f"proto={proto} "
            f"len={total_len}"
        ))
        stats["logged"] += 1


# ── Writer ────────────────────────────────────────────────

_f = None

def write(f, msg):
    ts   = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = f"[{ts}] {msg}"
    print(line)
    f.write(line + "\n")
    f.flush()


# ── Main ──────────────────────────────────────────────────

def main():
    print(f"sniff_all.py")
    print(f"  Interface:    {INTERFACE}")
    print(f"  Port filter:  {FILTER_PORT or 'ALL'}")
    print(f"  Mode:         "
          f"{'keywords-only' if KEYWORDS_ONLY else 'ALL traffic'}")
    print(f"  Payload:      "
          f"{'headers only' if NO_PAYLOAD else 'full'}")
    print(f"  Output:       {OUTFILE}\n")

    if os.geteuid() != 0:
        print("Not root! Trying unshare...")
        os.execvp("unshare", [
            "unshare", "--user",
            "--map-root-user", "--",
            sys.executable
        ] + sys.argv)
        sys.exit(1)

    socks = open_sockets(INTERFACES)
    if not socks:
        print("No interfaces opened!")
        sys.exit(1)

    stats = {
        "total": 0, "tcp": 0, "udp": 0,
        "logged": 0, "hits": 0
    }

    with open(OUTFILE, "w", buffering=1) as f:
        write(f, f"CAPTURE START: {datetime.now()}")
        write(f, f"Interface: {INTERFACE}")
        write(f, f"Port filter: {FILTER_PORT or 'ALL'}")
        write(f, f"Mode: "
                 f"{'keywords-only' if KEYWORDS_ONLY else 'full'}")
        write(f, "─" * 80)

        try:
            while True:
                for iface, sock in socks.items():
                    try:
                        raw, _ = sock.recvfrom(65535)
                        handle_packet(
                            raw, iface, f, stats
                        )
                    except socket.timeout:
                        continue
                    except Exception as e:
                        continue

                # Stats every 5000 packets
                if stats["total"] % 5000 == 0 \
                   and stats["total"] > 0:
                    write(f, (
                        f"[STATS] total={stats['total']} "
                        f"tcp={stats['tcp']} "
                        f"udp={stats['udp']} "
                        f"logged={stats['logged']} "
                        f"hits={stats['hits']}"
                    ))

        except KeyboardInterrupt:
            pass

        write(f, "─" * 80)
        write(f, f"CAPTURE END: {datetime.now()}")
        write(f, f"total={stats['total']} "
                 f"tcp={stats['tcp']} "
                 f"udp={stats['udp']} "
                 f"logged={stats['logged']} "
                 f"interesting={stats['hits']}")

    print(f"\n[*] Saved to {OUTFILE}")


if __name__ == "__main__":
    main()
