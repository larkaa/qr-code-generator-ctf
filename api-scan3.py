import requests, json
requests.packages.urllib3.disable_warnings()

services = {
    "api":         "https://api.studio.sparrow.cloud.echonet.net.intra",
    "gatekeeper":  "https://gatekeeper.studio.sparrow.cloud.echonet.net.intra",
    "offer":       "https://offer.studio.sparrow.cloud.echonet.net.intra",
    "project":     "https://project.studio.sparrow.cloud.echonet.net.intra",
    "wheelbuilder":"https://wheelbuilder.studio.sparrow.cloud.echonet.net.intra",
}

for name, base in services.items():
    r = requests.get(f"{base}/openapi.json", verify=False, timeout=5)
    spec = r.json()
    
    print(f"\n{'='*60}")
    print(f"{name}: {spec['info']['title']} v{spec['info']['version']}")
    print(f"{'='*60}")
    
    for path, methods in spec.get("paths", {}).items():
        for method, details in methods.items():
            tags = details.get("tags", [])
            summary = details.get("summary", "")
            # Check if endpoint needs auth
            security = details.get("security", "NOT_SET")
            auth = "🔓 NO AUTH" if security == [] else "🔒 AUTH" if security != "NOT_SET" else "?"
            print(f"  {method.upper():6} {path:50} {auth} {summary}")
            


# try /cookie endpoint            
base = "https://gatekeeper.studio.sparrow.cloud.echonet.net.intra"

# Get the full spec first
r = requests.get(f"{base}/openapi.json", verify=False)
spec = r.json()
print(json.dumps(spec["paths"], indent=2))

# Try the cookie endpoint
r = requests.get(f"{base}/cookie", verify=False)
print(f"\n/cookie: {r.status_code}")
print(f"Headers: {dict(r.headers)}")
print(f"Body: {r.text[:500]}")
print(f"Cookies: {dict(r.cookies)}")

# Try with your existing JWT
jwt = ""
r = requests.get(
    f"{base}/cookie",
    headers={"Authorization": f"Bearer {jwt}"},
    verify=False
)
print(f"\n/cookie with JWT: {r.status_code}")
print(r.text[:500])


## enumerate all API endpoints
# The openapi.json showed paths — call each one
# Start with GET endpoints (safe, read-only)

api_base = "https://api.studio.sparrow.cloud.echonet.net.intra"
r = requests.get(f"{api_base}/openapi.json", verify=False)
spec = r.json()

print("=== Codespace API - Testing all GET endpoints ===")
for path, methods in spec["paths"].items():
    if "get" in methods:
        url = f"{api_base}{path}"
        try:
            r = requests.get(url, verify=False, timeout=5)
            print(f"  {r.status_code} GET {path}")
            if r.status_code == 200:
                print(f"    {r.text[:200]}")
        except Exception as e:
            print(f"  ERR GET {path}: {e}")
            
            
# target mongo Express / pgweb

# pgweb is a PostgreSQL web UI — often no auth internally
pgweb_candidates = [
    "https://pgweb.studio.sparrow.cloud.echonet.net.intra",
    "http://198.18.121.198:80",   # mongo-express
    "http://198.18.121.198:8081",
]

for url in pgweb_candidates:
    try:
        r = requests.get(url, verify=False, timeout=5,
                        allow_redirects=False)
        print(f"{url}: {r.status_code}")
        if r.status_code == 200:
            print(f"  {r.text[:300]}")
    except Exception as e:
        print(f"{url}: {type(e).__name__}")

# Also resolve the internal hostname
import socket
for hostname in [
    "pgweb.studio.sparrow.cloud.echonet.net.intra",
    "mongol.studio.sparrow.cloud.echonet.net.intra",
    "redisc.studio.sparrow.cloud.echonet.net.intra",
]:
    try:
        ip = socket.gethostbyname(hostname)
        print(f"{hostname} -> {ip}")
        r = requests.get(f"https://{hostname}", 
                        verify=False, timeout=5)
        print(f"  {r.status_code} {r.text[:200]}")
    except Exception as e:
        print(f"{hostname}: {e}")


# wheelbuilder API with /builder POST

base = "https://wheelbuilder.studio.sparrow.cloud.echonet.net.intra"

# Get full spec
r = requests.get(f"{base}/openapi.json", verify=False)
spec = r.json()
print(json.dumps(spec, indent=2))

# The /builder endpoint builds wheels
# Try submitting a malicious package build
r = requests.post(
    f"{base}/builder",
    json={
        "package": "requests",
        "version": "2.28.0"
    },
    verify=False,
    timeout=10
)
print(f"\n/builder POST: {r.status_code}")
print(r.text[:500])


# kube-state-metrics direct access...
kube_state = "http://198.18.120.137:8080"

endpoints = [
    "/metrics",      # all metrics including secret names
    "/healthz",
    "/",
]

for ep in endpoints:
    r = requests.get(f"{kube_state}{ep}", timeout=5)
    print(f"{ep}: {r.status_code} ({len(r.content)}b)")
    if r.status_code == 200 and ep == "/metrics":
        # Find all secret-related metrics
        for line in r.text.splitlines():
            if 'secret' in line.lower() and not line.startswith('#'):
                print(f"  {line[:200]}")
                
                
