#!/usr/bin/env python3
"""
Targeted API Endpoint Scanner
Scans known services with service-specific endpoint lists
Usage: python3 api_scan.py
"""

import requests
import concurrent.futures
import urllib3
import json
from datetime import datetime

urllib3.disable_warnings()

# ============================================================
# TARGETS parsed from port scan
# ============================================================
TARGETS = [
    # Vault Secrets Operator (metrics)
    {"ip": "198.18.116.30",  "port": 8081,  "service": "vault-secrets-operator", "proto": "http"},
    {"ip": "198.18.116.30",  "port": 8443,  "service": "vault-secrets-operator", "proto": "https"},

    # Vault Injector
    {"ip": "198.18.14.19",   "port": 443,   "service": "vault-injector",         "proto": "https"},
    {"ip": "198.18.116.29",  "port": 8080,  "service": "vault-injector",         "proto": "http"},
    {"ip": "198.18.124.207", "port": 8080,  "service": "vault-injector",         "proto": "http"},

    # Traefik
    {"ip": "198.18.116.44",  "port": 8080,  "service": "traefik",                "proto": "http"},
    {"ip": "198.18.116.44",  "port": 9100,  "service": "traefik-metrics",        "proto": "http"},
    {"ip": "198.18.124.228", "port": 8080,  "service": "traefik",                "proto": "http"},

    # Sparrow Traefik
    {"ip": "198.18.116.3",   "port": 8080,  "service": "sparrow-traefik",        "proto": "http"},
    {"ip": "198.18.124.197", "port": 8080,  "service": "sparrow-traefik",        "proto": "http"},

    # Prometheus stack
    {"ip": "198.18.19.18",   "port": 9090,  "service": "prometheus",             "proto": "http"},
    {"ip": "198.18.3.197",   "port": 8080,  "service": "prometheus-operator",    "proto": "http"},
    {"ip": "198.18.12.37",   "port": 9093,  "service": "alertmanager",           "proto": "http"},
    {"ip": "198.18.12.37",   "port": 4180,  "service": "alertmanager-proxy",     "proto": "http"},
    {"ip": "198.18.13.70",   "port": 9100,  "service": "node-exporter",          "proto": "http"},

    # Sparrow RBAC API
    {"ip": "198.18.11.167",  "port": 443,   "service": "sparrow-rbac-api",       "proto": "https"},
    {"ip": "198.18.116.206", "port": 5000,  "service": "sparrow-rbac-api",       "proto": "http"},
    {"ip": "198.18.116.206", "port": 10443, "service": "sparrow-rbac-api",       "proto": "https"},
    {"ip": "198.18.121.207", "port": 5000,  "service": "sparrow-rbac-api",       "proto": "http"},
    {"ip": "198.18.121.207", "port": 10443, "service": "sparrow-rbac-api",       "proto": "https"},

    # Gatekeeper API
    {"ip": "198.18.26.127",  "port": 443,   "service": "gatekeeper-api",         "proto": "https"},
    {"ip": "198.18.121.199", "port": 10443, "service": "gatekeeper-api",         "proto": "https"},
    {"ip": "198.18.116.199", "port": 10443, "service": "gatekeeper-api",         "proto": "https"},

    # Offer API
    {"ip": "198.18.4.197",   "port": 443,   "service": "offer-api",              "proto": "https"},
    {"ip": "198.18.121.211", "port": 10443, "service": "offer-api",              "proto": "https"},

    # Project API
    {"ip": "198.18.26.142",  "port": 443,   "service": "project-api",            "proto": "https"},
    {"ip": "198.18.121.203", "port": 10443, "service": "project-api",            "proto": "https"},

    # Sparrow Front
    {"ip": "198.18.4.206",   "port": 80,    "service": "sparrow-front",          "proto": "http"},
    {"ip": "198.18.121.248", "port": 8080,  "service": "sparrow-front",          "proto": "http"},

    # Redis Commander
    {"ip": "198.18.121.197", "port": 5000,  "service": "redis-commander",        "proto": "http"},
    {"ip": "198.18.121.197", "port": 10443, "service": "redis-commander",        "proto": "https"},

    # Sparrot
    {"ip": "198.18.3.120",   "port": 443,   "service": "sparrot",                "proto": "https"},
    {"ip": "198.18.3.120",   "port": 10129, "service": "sparrot",                "proto": "http"},

    # Kubelet (node level - high value)
    {"ip": "10.26.163.7",    "port": 10250, "service": "kubelet",                "proto": "https"},
    {"ip": "10.26.163.10",   "port": 10250, "service": "kubelet",                "proto": "https"},
    {"ip": "10.26.163.29",   "port": 10250, "service": "kubelet",                "proto": "https"},

    # Node exporter
    {"ip": "10.26.163.7",    "port": 9100,  "service": "node-exporter",          "proto": "http"},
]

# ============================================================
# SERVICE-SPECIFIC ENDPOINT LISTS
# ============================================================
ENDPOINTS = {

    "vault-injector": [
        # Vault Agent Injector webhook and health
        "/",
        "/health/ready",
        "/health/live",
        "/mutate",
        # Vault API (injector may proxy to vault)
        "/v1/sys/health",
        "/v1/sys/seal-status",
        "/v1/sys/auth",
        "/v1/sys/mounts",
        "/v1/sys/policies/acl",
        "/v1/secret/",
        "/v1/secret/metadata/",
        "/v1/kv/",
        "/v1/auth/kubernetes/login",
        "/v1/auth/token/lookup-self",
        "/v1/identity/entity/id",
    ],

    "vault-secrets-operator": [
        "/",
        "/metrics",          # Prometheus metrics — leaks secret names!
        "/healthz",
        "/readyz",
        "/v1/",
    ],

    "traefik": [
        # Traefik dashboard — often unauthenticated
        "/",
        "/dashboard/",
        "/api/",
        "/api/rawdata",       # ALL routes and services!
        "/api/http/routers",  # all HTTP routes
        "/api/http/services", # all backend services
        "/api/http/middlewares",
        "/api/tcp/routers",
        "/api/entrypoints",
        "/api/overview",
        "/api/version",
        "/metrics",
        "/ping",
        "/health",
    ],

    "sparrow-traefik": [
        "/",
        "/dashboard/",
        "/api/rawdata",
        "/api/http/routers",
        "/api/http/services",
        "/api/overview",
        "/ping",
        "/metrics",
    ],

    "prometheus": [
        "/",
        "/graph",
        "/api/v1/query?query=up",
        "/api/v1/targets",          # all monitored targets
        "/api/v1/rules",            # alerting rules
        "/api/v1/alerts",
        "/api/v1/label/__name__/values",  # all metric names
        "/api/v1/series?match[]=up",
        "/api/v1/metadata",
        "/api/v1/status/config",    # full prometheus config!
        "/api/v1/status/flags",
        "/api/v1/status/runtimeinfo",
        "/api/v1/status/tsdb",
        "/metrics",
        "/federate",                # federation endpoint - all metrics
    ],

    "prometheus-operator": [
        "/",
        "/metrics",
        "/healthz",
        "/readyz",
    ],

    "alertmanager": [
        "/",
        "/api/v2/alerts",
        "/api/v2/silences",
        "/api/v2/receivers",
        "/api/v2/status",
        "/metrics",
        "/healthz",
        "/-/healthy",
        "/-/ready",
    ],

    "alertmanager-proxy": [
        "/",
        "/oauth2/",
        "/ping",
    ],

    "node-exporter": [
        "/",
        "/metrics",      # ALL node metrics — CPU, memory, disk, network
    ],

    "sparrow-rbac-api": [
        # Common REST API patterns
        "/",
        "/health",
        "/healthz",
        "/ready",
        "/readyz",
        "/ping",
        "/metrics",
        "/version",
        "/info",
        # Auth endpoints
        "/auth",
        "/auth/login",
        "/auth/token",
        "/auth/refresh",
        "/login",
        "/token",
        # RBAC specific
        "/api/v1/roles",
        "/api/v1/users",
        "/api/v1/permissions",
        "/api/v1/groups",
        "/api/v1/bindings",
        "/api/v1/policies",
        "/api/v1/access",
        "/api/v1/me",
        "/api/v1/whoami",
        # v2
        "/api/v2/roles",
        "/api/v2/users",
        "/api/v2/permissions",
        # Swagger/OpenAPI docs
        "/swagger",
        "/swagger-ui",
        "/swagger-ui.html",
        "/swagger/index.html",
        "/openapi.json",
        "/openapi.yaml",
        "/docs",
        "/redoc",
        "/api-docs",
        "/api/docs",
    ],

    "gatekeeper-api": [
        "/",
        "/health",
        "/healthz",
        "/ping",
        "/version",
        "/metrics",
        # Auth / token
        "/auth",
        "/auth/token",
        "/auth/login",
        "/token",
        "/oauth2/token",
        "/oauth2/authorize",
        # Gatekeeper specific
        "/api/v1/access",
        "/api/v1/check",
        "/api/v1/permissions",
        "/api/v1/users",
        "/api/v1/gates",
        "/api/v1/resources",
        "/api/v1/me",
        # Swagger
        "/swagger",
        "/openapi.json",
        "/docs",
    ],

    "offer-api": [
        "/",
        "/health",
        "/healthz",
        "/ping",
        "/version",
        "/metrics",
        "/api/v1/offers",
        "/api/v1/resources",
        "/api/v1/quotas",
        "/api/v1/users",
        "/api/v1/projects",
        "/api/v1/allocations",
        "/api/v1/me",
        "/swagger",
        "/openapi.json",
        "/docs",
    ],

    "project-api": [
        "/",
        "/health",
        "/healthz",
        "/ping",
        "/metrics",
        "/api/v1/projects",
        "/api/v1/users",
        "/api/v1/members",
        "/api/v1/roles",
        "/api/v1/resources",
        "/api/v1/me",
        "/api/v1/workspaces",
        "/api/v1/namespaces",
        "/swagger",
        "/openapi.json",
        "/docs",
    ],

    "sparrow-front": [
        "/",
        "/index.html",
        "/static/",
        "/assets/",
        # JS bundles often contain API URLs and config
        "/static/js/main.js",
        "/static/js/main.chunk.js",
        "/static/js/bundle.js",
        "/asset-manifest.json",
        "/manifest.json",
        "/config.js",
        "/config.json",
        "/env.js",
        "/robots.txt",
        "/sitemap.xml",
        # Common SPA routes that reveal structure
        "/api/",
        "/login",
        "/admin",
    ],

    "redis-commander": [
        "/",
        "/health",
        # Redis Commander web UI
        "/api/server-info",
        "/api/keys",
        "/api/key",
        "/api/keys/*",
        "/api/db/0/keys",    # database 0
        "/api/db/1/keys",    # database 1
        "/api/connections",
    ],

    "sparrot": [
        "/",
        "/health",
        "/healthz",
        "/ping",
        "/metrics",
        "/version",
        "/api/v1/",
        "/api/v1/jobs",
        "/api/v1/tasks",
        "/api/v1/status",
        "/api/v1/run",
        "/api/v1/execute",
        "/swagger",
        "/docs",
    ],

    "kubelet": [
        # Kubelet API — if anonymous access enabled = critical
        "/healthz",
        "/pods",             # list ALL pods on this node
        "/runningpods",      # currently running pods
        "/metrics",
        "/metrics/cadvisor", # container metrics
        "/stats/",
        "/stats/summary",
        "/spec/",
        "/logs/",
        # Exec into containers (websocket but test if endpoint exists)
        "/run/",
        "/exec/",
        "/attach/",
        "/portForward/",
        "/containerLogs/",
    ],
}

# Fallback for unknown services
DEFAULT_ENDPOINTS = [
    "/",
    "/health",
    "/healthz",
    "/ready",
    "/readyz",
    "/ping",
    "/version",
    "/metrics",
    "/info",
    "/status",
    "/api/",
    "/api/v1/",
    "/api/v2/",
    "/swagger",
    "/openapi.json",
    "/docs",
]

# ============================================================
# SCANNER
# ============================================================

def probe_endpoint(target, endpoint, timeout=5):
    """Probe a single endpoint, return result dict"""
    ip      = target["ip"]
    port    = target["port"]
    proto   = target["proto"]
    service = target["service"]

    url = f"{proto}://{ip}:{port}{endpoint}"

    try:
        r = requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0",
                "Accept": "application/json, text/html, */*",
            }
        )

        # Determine interest level
        interesting = r.status_code not in [404, 405, 301, 302]
        content_type = r.headers.get("Content-Type", "")
        length = len(r.content)

        # Peek at content
        try:
            preview = r.json()
            preview_str = json.dumps(preview)[:200]
            is_json = True
        except:
            preview_str = r.text[:200].replace('\n', ' ').strip()
            is_json = False

        return {
            "url":          url,
            "service":      service,
            "endpoint":     endpoint,
            "status":       r.status_code,
            "length":       length,
            "content_type": content_type,
            "is_json":      is_json,
            "preview":      preview_str,
            "interesting":  interesting,
        }

    except requests.exceptions.ConnectTimeout:
        return None
    except requests.exceptions.ConnectionError:
        return None
    except Exception as e:
        return None


def scan_target(target):
    """Scan all endpoints for a single target"""
    service  = target["service"]
    ip       = target["ip"]
    port     = target["port"]
    proto    = target["proto"]

    endpoints = ENDPOINTS.get(service, DEFAULT_ENDPOINTS)

    print(f"\n{'='*60}")
    print(f"[{service}] {proto}://{ip}:{port}")
    print(f"{'='*60}")

    findings = []

    for endpoint in endpoints:
        result = probe_endpoint(target, endpoint)
        if result is None:
            continue

        status = result["status"]
        length = result["length"]

        # Color coding via symbols
        if status == 200:
            sym = "✓"
        elif status in [201, 202, 204]:
            sym = "✓"
        elif status == 401:
            sym = "🔑"  # auth required — endpoint EXISTS
        elif status == 403:
            sym = "🔒"  # forbidden — endpoint EXISTS
        elif status == 500:
            sym = "💥"  # server error — interesting
        elif status in [404, 405]:
            sym = "✗"
        else:
            sym = "?"

        line = f"  {sym} {status} {endpoint:45} {length:6}b"

        if result["interesting"]:
            print(line)
            if result["preview"] and status == 200:
                print(f"       {result['preview'][:150]}")
            findings.append(result)

    return findings


def run_scan(workers=10):
    """Run full scan with thread pool"""
    print(f"[*] Starting API scan at {datetime.now().strftime('%H:%M:%S')}")
    print(f"[*] Targets: {len(TARGETS)} | Workers: {workers}")

    all_findings = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_target, t): t for t in TARGETS}
        for future in concurrent.futures.as_completed(futures):
            findings = future.result()
            if findings:
                all_findings.extend(findings)

    # ---- Summary ----
    print(f"\n{'='*60}")
    print("SUMMARY — INTERESTING FINDINGS")
    print(f"{'='*60}")

    # Group by status
    by_status = {}
    for f in all_findings:
        s = f["status"]
        by_status.setdefault(s, []).append(f)

    for status in sorted(by_status.keys()):
        findings = by_status[status]
        label = {
            200: "✓  200 OK — ACCESSIBLE",
            401: "🔑 401 UNAUTHORIZED — endpoint exists, needs auth",
            403: "🔒 403 FORBIDDEN — endpoint exists",
            500: "💥 500 SERVER ERROR — interesting",
        }.get(status, f"   {status}")

        print(f"\n{label} ({len(findings)} endpoints):")
        for f in findings:
            print(f"  {f['url']}")
            if f['status'] == 200 and f['preview']:
                print(f"    >> {f['preview'][:120]}")

    # Save results
    output_file = f"api_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as out:
        json.dump(all_findings, out, indent=2)
    print(f"\n[*] Results saved to {output_file}")

    return all_findings


if __name__ == "__main__":
    run_scan(workers=15)
