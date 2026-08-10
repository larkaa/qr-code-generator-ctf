#!/usr/bin/env python3
import requests, re, socket
from datetime import datetime

requests.packages.urllib3.disable_warnings()
PROMETHEUS = "http://198.18.19.18:9090"

def promql(query):
    r = requests.get(
        f"{PROMETHEUS}/api/v1/query",
        params={"query": query},
        timeout=30
    )
    return r.json().get("data", {}).get("result", [])

def check_port(ip, port, timeout=2):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        ok = s.connect_ex((ip, int(port))) == 0
        s.close()
        return ok
    except:
        return False

# ── Get actual pod IPs ────────────────────────────────────
# kube_pod_status_pod_ip has the REAL pod IP, not service IP
results = promql(
    'kube_pod_status_pod_ip{namespace="sparrow-studio-prod"}'
)

print(f"[*] {datetime.now().strftime('%H:%M:%S')}")
print(f"\n  {'USER':12} {'KIND':12} {'POD IP':18} "
      f"{'PORT':6} {'STATUS'}")
print(f"  {'─'*12} {'─'*12} {'─'*18} {'─'*6} {'─'*6}")

for item in sorted(results,
                   key=lambda x: x["metric"].get("pod","")):
    m      = item.get("metric", {})
    pod    = m.get("pod", "")
    pod_ip = m.get("pod_ip", "")   # ← actual pod IP

    if not pod.startswith("sop-") or not pod_ip:
        continue

    uid_m  = re.search(r'sop-([a-z0-9]+)-reg', pod)
    pfx_m  = re.search(
        r'(sop-[a-z0-9]+-reg-[a-z]+-[a-z]--[a-f0-9]+)',
        pod
    )
    kind   = "jupyterlab" if "-jl-"  in pod else \
             "vscode"     if "-c-3-" in pod else "other"
    uid    = uid_m.group(1) if uid_m else "?"
    prefix = f"/{pfx_m.group(1)}" if pfx_m else ""

    # Check which port is open on the real pod IP
    port   = "8081"  if check_port(pod_ip, 8081)  else \
             "10443" if check_port(pod_ip, 10443) else "NONE"
    ok     = "✓" if port != "NONE" else "✗"

    print(f"  {uid:12} {kind:12} {pod_ip:18} {port:6} {ok}")
    if port != "NONE":
        print(f"    http://{pod_ip}:{port}{prefix}/api/kernels")
