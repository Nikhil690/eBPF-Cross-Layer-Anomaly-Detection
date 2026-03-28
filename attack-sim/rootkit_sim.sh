#!/usr/bin/env bash
# rootkit_sim.sh — rootkit network behavior simulation
# Slow periodic beaconing + port knocking sequence
set -euo pipefail

TARGET="${1:-93.184.216.34}"
echo "[*] Rootkit/beacon simulation → $TARGET"

python3 - <<PYEOF
import socket, time, subprocess

target = "$TARGET"

# Port-knocking sequence (common rootkit activation pattern)
knock_ports = [7000, 8000, 9000, 10000, 7001]
for port in knock_ports:
    try:
        s = socket.socket()
        s.settimeout(0.05)
        s.connect((target, port))
        s.close()
    except:
        pass
    time.sleep(0.05)

# Periodic beaconing: slow, regular connects to C2
# (distinctive pattern: constant interval, always same port)
for _ in range(15):
    try:
        s = socket.socket()
        s.settimeout(0.2)
        s.connect((target, 443))
        s.close()
    except:
        pass
    time.sleep(0.3)  # regular 300ms beacon interval

print("[*] Rootkit sim: knock sequence + 15 beacon pulses")
PYEOF

echo "[*] Rootkit simulation complete"
