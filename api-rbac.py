# ============================================================
# Try RBAC API with your existing JWT
# ============================================================

# Decode your JWT from the Jupyter cookie
# eyJ1c2VybmFtZSI6IjY4ZDAx...
# decoded to {"username": "68d0...", "name": "Anonymous Pasiphae"}
# PLATFORM JWT --- to RBAC API ?

jwt = "YOUR_FULL_JWT_HERE"  

base = "https://198.18.121.207:10443"

# Try all auth header formats
auth_formats = [
    {"Authorization": f"Bearer {jwt}"},
    {"Authorization": f"JWT {jwt}"},
    {"X-Auth-Token": jwt},
    {"X-User-Token": jwt},
    {"Cookie": f"token={jwt}; session={jwt}"},
]

test_endpoints = [
    "/api/v1/me",
    "/api/v1/users",  
    "/api/v1/roles",
    "/api/v1/permissions",
    "/health",
]

for hdrs in auth_formats:
    auth_type = list(hdrs.keys())[0]
    r = requests.get(f"{base}/api/v1/me",
                    headers=hdrs, verify=False, timeout=5)
    print(f"{auth_type}: {r.status_code} {r.text[:100]}")
    
    if r.status_code == 200:
        print(f"  *** AUTH WORKS with {auth_type}! ***")
        # Now enumerate everything
        for ep in test_endpoints:
            r2 = requests.get(f"{base}{ep}",
                             headers=hdrs,
                             verify=False, timeout=5)
            print(f"  {ep}: {r2.status_code} {r2.text[:200]}")
        break
