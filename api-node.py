# ============================================================
# Node exporter reveals filesystem, network, CPU of the NODE
# ============================================================
r = requests.get("http://198.18.13.70:9100/metrics")
metrics_text = r.text

# Parse into dict
metrics = {}
for line in metrics_text.splitlines():
    if line.startswith('#') or not line.strip():
        continue
    parts = line.split(' ')
    if len(parts) >= 2:
        name = parts[0]
        value = parts[-1]
        metrics[name] = value

# Extract interesting info
print("=== NODE INTELLIGENCE ===")

# Filesystem mounts
print("\nFilesystem mounts:")
for key, val in metrics.items():
    if 'filesystem' in key and 'mountpoint' in key:
        print(f"  {key} = {val}")

# Network interfaces
print("\nNetwork interfaces:")
for key, val in metrics.items():
    if 'network_receive_bytes' in key:
        print(f"  {key} = {val}")

# System info
print("\nSystem info:")
for key in ['node_uname_info', 'node_os_info', 
            'node_boot_time_seconds']:
    for metric_key, val in metrics.items():
        if key in metric_key:
            print(f"  {metric_key} = {val}")
