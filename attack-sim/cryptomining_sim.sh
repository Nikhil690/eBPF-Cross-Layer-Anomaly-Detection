#!/usr/bin/env bash
# cryptomining_sim.sh — cryptominer C2 pool connection simulation
# Stratum protocol: persistent TCP to pool port 3333/4444, repeated reconnects
set -euo pipefail

TARGET="${1:-93.184.216.34}"
echo "[*] Cryptomining pool simulation → $TARGET"

python3 - <<PYEOF
import socket, time

target = "$TARGET"
pool_ports = [3333, 4444, 14444, 45700]

# Miners make persistent connections with rapid reconnects on failure
for cycle in range(5):
    for port in pool_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((target, port))
            # Stratum subscribe message
            s.sendall(b'{"id":1,"method":"mining.subscribe","params":[]}\n')
            time.sleep(0.1)
            s.close()
        except:
            pass

print("[*] Cryptomining sim: 20 pool connection attempts (5 cycles x 4 ports)")
PYEOF

echo "[*] Cryptomining simulation complete"
