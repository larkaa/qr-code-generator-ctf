import websocket
import threading
import time
import uuid

VSCODE_HOST = "127.0.0.1"  # or your target
VSCODE_PORT = 8081
COMMAND     = "id && ls -lah && env\n"

output_lines = []
done         = threading.Event()
shell_ready  = threading.Event()

def on_message(ws, message):
    # Handle BINARY — VS Code terminal sends raw PTY bytes
    if isinstance(message, bytes):
        try:
            text = message.decode("utf-8", errors="replace")
        except:
            text = message.decode("latin-1", errors="replace")
    else:
        text = message

    output_lines.append(text)
    print(f"< {repr(text[:100])}")

    # Shell prompt = ready to receive commands
    if any(p in text for p in ["$", "#", "coder@", ">"]):
        shell_ready.set()

def on_open(ws):
    print("Connected — waiting for shell prompt...")
    got_prompt = shell_ready.wait(timeout=8)
    print(f"Prompt: {got_prompt}")

    # Send raw bytes — terminal expects raw PTY input
    print(f"Sending command...")
    ws.send(COMMAND.encode("utf-8"),
            opcode=websocket.ABNF.OPCODE_BINARY)
    time.sleep(4)

    # Marker to know when done
    ws.send(b"echo __DONE__\n",
            opcode=websocket.ABNF.OPCODE_BINARY)
    time.sleep(2)
    done.set()

def on_error(ws, error):
    print(f"Error: {error}")
    done.set()

def on_close(ws, *args):
    print("Closed")
    done.set()

# ============================================================
# Try the terminal path — raw binary WebSocket
# ============================================================
ws_paths = [
    f"ws://{VSCODE_HOST}:{VSCODE_PORT}/terminal",
    f"ws://{VSCODE_HOST}:{VSCODE_PORT}/vscode/terminal",
    f"ws://{VSCODE_HOST}:{VSCODE_PORT}/",
]

for ws_url in ws_paths:
    print(f"\n=== {ws_url} ===")
    output_lines.clear()
    done.clear()
    shell_ready.clear()

    ws = websocket.WebSocketApp(
        ws_url,
        header=[
            f"Origin: http://{VSCODE_HOST}:{VSCODE_PORT}",
        ],
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
    )

    t = threading.Thread(target=ws.run_forever)
    t.daemon = True
    t.start()
    done.wait(timeout=15)
    ws.close()
    t.join(timeout=2)

    output = "".join(output_lines)
    if len(output) > 20:
        print(f"\n*** OUTPUT on {ws_url} ***")
        print(output)
        if "__DONE__" in output:
            idx = output.find(COMMAND.strip())
            end = output.find("__DONE__")
            if idx != -1 and end != -1:
                print(f"\nCLEAN:\n{output[idx+len(COMMAND):end].strip()}")
        break
