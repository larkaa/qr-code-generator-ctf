# Port 8080 requires HTTPS (we saw "Client sent HTTP to HTTPS server")
# Switch to HTTPS

vault_injector_hosts = [
    "198.18.116.29",
    "198.18.120.132", 
    "198.18.124.207",
]

for host in vault_injector_hosts:
    base = f"https://{host}:8080"
    print(f"\n=== Vault Injector: {host} ===")
    
    for ep in ["/health/ready", "/health/live",
               "/v1/sys/health", "/v1/sys/seal-status",
               "/v1/sys/auth", "/v1/sys/mounts"]:
        try:
            r = requests.get(f"{base}{ep}",
                           verify=False, timeout=5)
            print(f"  {ep}: {r.status_code} {r.text[:150]}")
        except Exception as e:
            print(f"  {ep}: {type(e).__name__}")
