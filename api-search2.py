#!/usr/bin/env python3
"""
codespaces.py
Gets live user codespace pods and their IPs from Prometheus.
Always up to date — Prometheus scrapes every 30s.
"""
import requests
from datetime import datetime

requests.packages.urllib3.disable_warnings()

PROMETHEUS = "http://198.18.19.18:9090"

def promql(query):
    r = requests.get(
        f"{PROMETHEUS}/api/v1/query",
        params={"query": query},
        timeout=30
    )
    if r.status_code == 200:
        return r.json().get("data", {}).get("result", [])
    return []

def get_codespaces():
    print(f"[*] Querying Prometheus — {datetime.now().strftime('%H:%M:%S')}")

    # ── Source 1: Active scrape targets ───────────────────
    # Most reliable — only shows pods currently being scraped
    r = requests.get(
        f"{PROMETHEUS}/api/v1/targets",
        timeout=30
    )
    targets = r.json()["data"]["activeTargets"]

    pods = {}  # ip → info

    for t in targets:
        labels   = t.get("labels", {})
        pod      = labels.get("pod", "")
        instance = labels.get("instance", "")
        ns       = labels.get("namespace", "")
        job      = labels.get("job", "")
        health   = t.get("health", "?")

        if not pod.startswith("sop-") or \
           ns != "sparrow-studio-prod":
            continue

        # Extract IP from instance
        ip = instance.split(":")[0] if ":" in instance \
             else instance

        # Extract port
        port = instance.split(":")[1] if ":" in instance \
               else "?"

        # Parse user ID and kind from pod name
        import re
        uid_m  = re.search(r'sop-([a-z0-9]+)-reg', pod)
        user_id = uid_m.group(1) if uid_m else "?"
        kind    = "jupyterlab" if "-jl-"  in pod else \
                  "vscode"     if "-c-3-" in pod else \
                  "other"

        # Derive prefix (base URL)
        pfx_m  = re.search(
            r'(sop-[a-z0-9]+-reg-[a-z]+-[a-z]--[a-f0-9]+)',
            pod
        )
        prefix = f"/{pfx_m.group(1)}" if pfx_m else ""

        key = f"{ip}:{port}"
        if key not in pods:
            pods[key] = {
                "ip":      ip,
                "port":    port,
                "pod":     pod,
                "user_id": user_id,
                "kind":    kind,
                "prefix":  prefix,
                "health":  health,
                "jobs":    [],
            }
        pods[key]["jobs"].append(job)

    # ── Source 2: kube_service_info for ClusterIPs ────────
    # Catches pods that may not be scraped yet
    svc_results = promql(
        'kube_service_info{namespace="sparrow-studio-prod"}'
    )
    for item in svc_results:
        m   = item.get("metric", {})
        svc = m.get("service", "")
        ip  = m.get("cluster_ip", "")

        if not svc.startswith("sop-") or \
           not ip or ip == "None":
            continue

        import re
        uid_m  = re.search(r'sop-([a-z0-9]+)-reg', svc)
        user_id = uid_m.group(1) if uid_m else "?"
        kind    = "jupyterlab" if "-jl-"  in svc else \
                  "vscode"     if "-c-3-" in svc else \
                  "other"
        pfx_m  = re.search(
            r'(sop-[a-z0-9]+-reg-[a-z]+-[a-z]--[a-f0-9]+)',
            svc
        )
        prefix = f"/{pfx_m.group(1)}" if pfx_m else ""

        key = f"{ip}:?"
        if key not in pods:
            pods[key] = {
                "ip":      ip,
                "port":    "10443",
                "pod":     svc,
                "user_id": user_id,
                "kind":    kind,
                "prefix":  prefix,
                "health":  "svc",
                "jobs":    [],
            }

    return pods

def print_report(pods):
    # Group by user
    by_user = {}
    for info in pods.values():
        uid = info["user_id"]
        by_user.setdefault(uid, []).append(info)

    print(f"\n{'='*70}")
    print(f"  LIVE CODESPACES — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Total pods: {len(pods)} | Users: {len(by_user)}")
    print(f"{'='*70}")

    # Header
    print(f"\n  {'USER':12} {'KIND':12} {'IP':20} "
          f"{'PORT':6} {'PREFIX':40} {'STATUS'}")
    print(f"  {'─'*12} {'─'*12} {'─'*20} "
          f"{'─'*6} {'─'*40} {'─'*6}")

    for uid in sorted(by_user.keys()):
        for info in sorted(
            by_user[uid],
            key=lambda x: x["kind"]
        ):
            health = "✓" if info["health"] == "up" \
                     else "~" if info["health"] == "svc" \
                     else "✗"
            print(
                f"  {uid:12} "
                f"{info['kind']:12} "
                f"{info['ip']:20} "
                f"{info['port']:6} "
                f"{info['prefix']:40} "
                f"{health}"
            )

    # Quick-copy section
    print(f"\n{'='*70}")
    print(f"  QUICK COPY — API endpoints")
    print(f"{'='*70}")
    for info in sorted(pods.values(),
                       key=lambda x: x["user_id"]):
        if info["kind"] == "jupyterlab":
            print(f"\n  # {info['user_id']}")
            print(f"  http://{info['ip']}:{info['port']}"
                  f"{info['prefix']}/api/kernels")
            print(f"  http://{info['ip']}:{info['port']}"
                  f"{info['prefix']}/api/contents")

    # Save to file
    outfile = f"codespaces_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(outfile, "w") as f:
        f.write(f"CODESPACES SNAPSHOT — "
                f"{datetime.now()}\n\n")
        f.write(f"{'USER':12} {'KIND':12} {'IP':20} "
                f"{'PORT':6} {'PREFIX'}\n")
        f.write(f"{'─'*80}\n")
        for uid in sorted(by_user.keys()):
            for info in sorted(
                by_user[uid], key=lambda x: x["kind"]
            ):
                f.write(
                    f"{uid:12} "
                    f"{info['kind']:12} "
                    f"{info['ip']:20} "
                    f"{info['port']:6} "
                    f"{info['prefix']}\n"
                )
    print(f"\n[*] Saved → {outfile}")

if __name__ == "__main__":
    pods = get_codespaces()
    print_report(pods)
