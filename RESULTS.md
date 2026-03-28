# Test & Verification Guide — eBPF-CLA

This document is a step-by-step checklist to reproduce every result claimed in the paper from a clean environment. Each section states the expected output so you can confirm the system is working correctly at each stage.

---

## Environment Snapshot (Reference Run)

| Item | Value |
|---|---|
| OS | Ubuntu 24.04 |
| Kernel | `6.8.0-106-generic` |
| clang | 18.1.3 |
| Go | 1.25.6 linux/amd64 |
| Python | 3.12.3 |
| Interface | `ens3` |
| Date | 2026-03-28 |

---

## Step 0 — Prerequisites Check

Run every command below and verify the expected output before proceeding.

```bash
# Kernel must be >= 5.8 (ring buffer requirement)
uname -r
# Expected: 6.8.0-xxx  or any >=5.8 kernel

# BTF must be available (CO-RE portability)
ls -lh /sys/kernel/btf/vmlinux
# Expected: -r--r--r-- 1 root root ~6MB ...

# clang >= 14
clang --version | head -1
# Expected: Ubuntu clang version 18.x.x

# Go >= 1.21
go version
# Expected: go version go1.25.x linux/amd64

# libbpf headers
ls /usr/include/bpf/bpf_helpers.h
# Expected: /usr/include/bpf/bpf_helpers.h

# Python deps for evaluation
python3 -c "import sklearn, pandas, numpy; print('sklearn', sklearn.__version__)"
# Expected: sklearn 1.4.x
```

If any of these fail, install the missing tools:

```bash
sudo apt-get install -y clang llvm libbpf-dev golang-go
sudo apt-get install -y python3-sklearn python3-pandas python3-numpy
```

---

## Step 1 — Build

```bash
cd /home/ubuntu/ebpf-cla

# Compile eBPF C → Go skeletons → binary
make build
```

**Expected output:**

```
# go generate runs bpf2go for xdp.c, tc.c, tracepoint.c — no errors
# go build succeeds silently
```

Verify the binary exists:

```bash
ls -lh ebpf-cla
# Expected: -rwxrwxr-x ... ~5.6M ... ebpf-cla
file ebpf-cla
# Expected: ELF 64-bit LSB executable, x86-64 ...
```

If `make build` fails on `bpf_helpers.h not found`:

```bash
sudo apt-get install -y libbpf-dev
make build
```

---

## Step 2 — Attach Verification

Start the monitor and confirm all three hooks load cleanly.

```bash
sudo ./ebpf-cla ens3
```

**Expected first line:**

```
2026/03/28 HH:MM:SS [loader] attached XDP+TC on ens3, tracepoint sys_enter_connect
eBPF-CLA running on ens3 (Ctrl+C to stop)
```

In a second terminal, confirm the BPF programs are actually attached to the kernel:

```bash
sudo bpftool net list
```

**Expected:**

```
xdp:
ens3(2) driver id XX

tc:
ens3(2) tcx/egress tc_correlate prog_id XX link_id XX

flow_dissector:

netfilter:
```

Confirm the five BPF maps exist:

```bash
sudo bpftool map list | grep -E "flow_stats|cookie_map|corr_window|ring_events|proc_state"
```

**Expected (5 lines, one per map):**

```
XX: lru_hash  name flow_stats_map  ...  max_entries 65536 ...
XX: hash      name cookie_map      ...  max_entries 65536 ...
XX: lru_hash  name corr_window_map ...  max_entries 65536 ...
XX: ringbuf   name ring_events     ...  max_entries 16777216 ...
XX: hash      name proc_state_map  ...  max_entries 4096 ...
```

Stop with `Ctrl+C`. Verify programs detach cleanly:

```bash
sudo bpftool net list
# Expected: all sections empty (no xdp:, no tc:)
```

---

## Step 3 — XDP and TC Pipeline Smoke Test

This confirms the XDP map fills on real traffic AND the TC cookie map populates (the bug from TCXIngress→TCXEgress is fixed).

```bash
# Start monitor
sudo ./ebpf-cla ens3 &
CLA_PID=$!
sleep 3

# Generate 5 outbound connections
for i in $(seq 1 5); do curl -s -o /dev/null http://example.com; done
sleep 2

# XDP must have entries
sudo bpftool map dump name flow_stats_map 2>/dev/null | head -5
# Expected: JSON output with pkt_count > 0, byte_count > 0

# TC cookie map must have entries (empty = TC still on ingress, WRONG)
sudo bpftool map dump name cookie_map 2>/dev/null | head -5
# Expected: JSON output with non-zero values  (NOT "[]")

sudo kill $CLA_PID 2>/dev/null; wait 2>/dev/null
```

**Pass criteria:**
- `flow_stats_map` is non-empty → XDP is firing
- `cookie_map` is non-empty → TC egress is firing and cookies are being assigned

---

## Step 4 — Ring Buffer & Sweeper Smoke Test

This confirms events reach userspace via both paths (ring buffer for long-lived flows, sweeper for short-lived flows).

```bash
sudo ./ebpf-cla ens3 &
CLA_PID=$!
sleep 3

# Generate a burst of short connections (sweeper path)
python3 -c "
import socket
for port in range(80, 130):
    try:
        s=socket.socket(); s.settimeout(0.05)
        s.connect(('93.184.216.34', port)); s.close()
    except: pass
"

sleep 5
sudo kill $CLA_PID 2>/dev/null; wait 2>/dev/null
```

**Expected log output** (will appear in the terminal running ebpf-cla):

```
[info ] score=X.XX layers=XT.. pkt=XXX total_events=50 alerts=X
```

The `layers=XT..` confirms XDP (X) and TC (T) are both contributing to corr-records. If you see `layers=.T..` only, XDP is not matching flows — check that traffic is traversing `ens3` (not loopback).

---

## Step 5 — Attack Detection Smoke Test

Quick manual verification that port scan and SYN flood trigger alerts.

```bash
# Terminal 1 — start monitor
sudo ./ebpf-cla ens3

# Terminal 2 — port scan (50 ports)
python3 -c "
import socket
for port in range(1, 51):
    try:
        s=socket.socket(); s.settimeout(0.05)
        s.connect(('93.184.216.34', port)); s.close()
    except: pass
print('scan done')
"
```

**Expected in Terminal 1** (within 10 seconds of scan starting):

```
[ALERT] score=XX.XX layers=XT.. syn=X pkt=X pid=0 comm= cookie=X
```

The score should be significantly above 4.0 (typically 15–40 for a port scan). If you see `[info]` lines but no `[ALERT]`:
- Verify the warmup guard has passed (need ≥50 events before scoring begins)
- Generate some benign traffic first: `curl -s -o /dev/null http://example.com` repeated 10 times

---

## Step 6 — BPF Program Overhead Measurement

Reproduces the latency numbers in the paper (Table V).

```bash
# Enable BPF stats
sudo sysctl -w kernel.bpf_stats_enabled=1

# Start monitor
sudo ./ebpf-cla ens3 > /dev/null 2>&1 &
CLA_PID=$!
sleep 3

# Baseline read (before traffic)
T0_XDP=$(sudo bpftool prog show name xdp_flow_monitor 2>/dev/null | grep -oP 'run_time_ns \K\d+' || echo 0)
T0_TC=$(sudo bpftool prog show name tc_correlate 2>/dev/null | grep -oP 'run_time_ns \K\d+' || echo 0)

# Generate 2000 connections
python3 -c "
import socket
for _ in range(2000):
    try:
        s=socket.socket(); s.settimeout(0.05)
        s.connect(('93.184.216.34', 80)); s.close()
    except: pass
"
sleep 2

# After read
T1_XDP=$(sudo bpftool prog show name xdp_flow_monitor 2>/dev/null | grep -oP 'run_time_ns \K\d+' || echo 0)
T1_TC=$(sudo bpftool prog show name tc_correlate 2>/dev/null | grep -oP 'run_time_ns \K\d+' || echo 0)
C1_XDP=$(sudo bpftool prog show name xdp_flow_monitor 2>/dev/null | grep -oP 'run_cnt \K\d+' || echo 0)
C1_TC=$(sudo bpftool prog show name tc_correlate 2>/dev/null | grep -oP 'run_cnt \K\d+' || echo 0)

python3 -c "
xdp_ns=$((T1_XDP - T0_XDP)); tc_ns=$((T1_TC - T0_TC))
xdp_c=$C1_XDP; tc_c=$C1_TC
print(f'XDP: {xdp_c} runs  avg={xdp_ns/max(xdp_c,1):.0f} ns/call')
print(f'TC:  {tc_c} runs  avg={tc_ns/max(tc_c,1):.0f} ns/call')
"

sudo kill $CLA_PID 2>/dev/null; wait 2>/dev/null
sudo sysctl -w kernel.bpf_stats_enabled=0
```

**Expected output (reproduce within ±20%):**

```
XDP:  ~1600 runs  avg=1970 ns/call
TC:   ~3500 runs  avg=4985 ns/call
```

---

## Step 7 — Full Dataset Collection

Collects the labelled CSV used for Table IV. Runtime: ~5 minutes.

```bash
sudo bash results/collect_sessions.sh ens3 2>&1 | tee /tmp/collect_out.txt
```

**Expected final lines:**

```
[collect] COMPLETE → results/raw/sessions_YYYYMMDD_HHMMSS.csv
[collect] total events: ~4000–6000
  benign:        ~400–600
  cryptomining:  ~180–400
  exfil:         ~180–400
  portscan:      ~800–1400
  privesc:       ~180–400
  rootkit:       ~200–450
  synflood:      ~600–1000
```

Save the CSV path:

```bash
CSV=$(ls results/raw/sessions_*.csv | tail -1)
echo "CSV: $CSV"
```

---

## Step 8 — Evaluate Results (Table IV Reproduction)

```bash
python3 results/analysis/evaluate.py "$CSV"
```

**Expected output (reproduce within ±5 pp on each metric):**

```
================================================================
  Per-class recall (Rule (pkt+windows))
================================================================
  Label                  Flows    Recall%
  ---------------------- -----  ---------
  benign                   ~4        —     (FP count noted)
  cryptomining            ~40     ≥90.0% ✓
  exfil                   ~15     ≥80.0% ✓
  portscan               ~600     ≥99.0% ✓
  privesc                 ~20     ≥85.0% ✓
  rootkit                 ~25     ≥85.0% ✓
  synflood               ~500     ≥99.0% ✓

================================================================
  Detector comparison  (flow-level, benign=0 vs attack=1)
================================================================
  Detector                       Prec     Rec      F1
  Rule (pkt+windows)            ~0.930  ~0.987   ~0.957 ★
  Isolation Forest              ~0.79   ~0.03    ~0.06
  OC-SVM                        ~0.68   ~0.01    ~0.02
  Ensemble (majority)           ~0.74   ~0.03    ~0.05
```

**Reference run (2026-03-28, `sessions_merged.csv`, 1,530 flows):**

```
Rule (pkt+windows)   Prec=0.930  Rec=0.987  F1=0.957
Isolation Forest     Prec=0.792  Rec=0.030  F1=0.057
OC-SVM               Prec=0.680  Rec=0.012  F1=0.024
Ensemble             Prec=0.741  Rec=0.028  F1=0.054

Per-category recall:
  portscan      99.6%
  synflood      99.5%
  cryptomining  93.0%
  privesc       87.5%
  rootkit       85.7%
  exfil         82.4%
```

---

## Step 9 — Memory Overhead

```bash
sudo ./ebpf-cla ens3 > /dev/null 2>&1 &
CLA_PID=$!
sleep 3

# BPF map memory (kernel-side)
echo "=== BPF map memory ==="
sudo bpftool map list | grep memlock | awk '{sum+=$NF} END {printf "Total: %.1f MB\n", sum/1048576}'

# Userspace process memory
echo "=== Userspace process ==="
ps -p $CLA_PID -o pid,rss,%mem --no-headers

sudo kill $CLA_PID 2>/dev/null; wait 2>/dev/null
```

**Expected:**

```
=== BPF map memory ===
Total: 43.1 MB

=== Userspace process ===
  XXXX  6960  0.3
```

BPF maps break down as:
- `flow_stats_map` (LRU 65536 × 56B) → ~8.9 MB
- `cookie_map` (HASH 65536 × 8B) → ~5.8 MB
- `corr_window_map` (LRU 65536 × 128B) → ~13.1 MB
- `ring_events` (RINGBUF 16 MB) → ~16.9 MB

---

## Step 10 — Single Continuous Session

Full end-to-end single-process session (reproduces `single_20260328_104918.csv`). Runtime: ~7 minutes.

```bash
sudo bash results/single_session_eval.sh ens3 2>&1 | tee /tmp/single_out.txt
```

**Expected final output:**

```
[single] COMPLETE
[single] Events: ~10,000–15,000
[single] Timeline:
  HH:MM:SS BENIGN_START
  HH:MM:SS BENIGN_END
  HH:MM:SS PORTSCAN_START
  ...
```

Inspect z-score distribution across phases:

```bash
SINGLE_CSV=$(ls results/raw/single_*.csv | tail -1)
python3 - << 'EOF'
import pandas as pd

df = pd.read_csv('/home/ubuntu/ebpf-cla/results/raw/single_20260328_104918.csv')
df.columns = df.columns.str.strip()
df['score'] = pd.to_numeric(df['score'], errors='coerce').fillna(0)

# Events with score > 4.0 = ALERT
alerts = df[df['score'] > 4.0]
print(f"Total events: {len(df)}")
print(f"Alerts (score > 4.0): {len(alerts)}")
print(f"Alert precision estimate: {len(alerts)/max(len(df),1)*100:.2f}% of all events")
print(f"Score p99 overall: {df['score'].quantile(0.99):.2f}")
print(f"\nTop 5 highest-score events:")
print(df.nlargest(5, 'score')[['timestamp','score','layers','pkt_count','syn_count']].to_string(index=False))
EOF
```

**Expected:**

```
Total events: ~13000
Alerts (score > 4.0): ~140
Score p99 overall: ~5.0

Top 5 highest-score events — scores in range 8–15, layers=XT..
```

---

## Checklist Summary

| Step | Test | Pass Condition |
|---|---|---|
| 0 | Prerequisites | All tools found, BTF present |
| 1 | Build | Binary exists, ~5.6 MB |
| 2 | Attach | `bpftool net list` shows XDP + tcx/egress |
| 3 | XDP + TC smoke | `flow_stats_map` AND `cookie_map` non-empty after curl |
| 4 | Ring buffer + sweeper | `[info]` lines appear in log after short connections |
| 5 | Alert firing | `[ALERT] score>4` within 10 s of port scan start |
| 6 | Overhead | XDP ~1970 ns/call, TC ~4985 ns/call (±20%) |
| 7 | Dataset collection | ~4000–6000 events, 7 labelled classes |
| 8 | Evaluation | Rule F1 ≥ 0.93, portscan recall ≥ 99% |
| 9 | Memory | BPF maps ~43 MB, RSS ~7 MB |
| 10 | Single session | ~13000 events, alerts during portscan phase |

All 10 steps passing = paper results are fully reproduced.

---

## Troubleshooting

### `cookie_map` is empty after curl
TC is on ingress. Rebuild after verifying `loader.go` has `ebpf.AttachTCXEgress` (not `AttachTCXIngress`).

### No `[ALERT]` events during port scan
The warmup guard (`n<50`) suppresses scoring until 50 events are seen. Generate benign traffic first (`curl -s http://example.com` × 10), then scan.

### `bpf_get_socket_cookie()` returns 0 in TC
This is the ingress bug — see above. Only egress packets have `skb->sk` set.

### `bpf_helpers.h not found` during `go generate`
```bash
sudo apt-get install -y libbpf-dev
```

### XDP attach fails: `operation not permitted`
```bash
sudo setcap cap_bpf,cap_net_admin,cap_perfmon+ep ./ebpf-cla
# or just run with sudo
```

### `flow_stats_map` is empty even after curl
Traffic is going through loopback, not `ens3`. Confirm the target IP routes via `ens3`:
```bash
ip route get 93.184.216.34
# Expected: ... dev ens3 ...
```
If traffic goes via `lo`, use the machine's own external IP or switch to `lo` interface (adjust attack-sim target to `127.0.0.1`).

### Low event count during port scan phase
Short-lived connections need the sweeper. Verify `sweepCorrWindow()` goroutine is running:
```bash
# Check corr_window_map is draining over time
watch -n1 "sudo bpftool map dump name corr_window_map 2>/dev/null | grep -c cookie"
# Count should fluctuate (entries being created and swept), not grow monotonically
```

### sklearn models report F1 ~0.05
This is expected — the sklearn models suffer from benign/attack feature overlap at the single-flow level (short curl connections look identical to portscan probes). The rule-based detector (`F1=0.957`) is the primary result. See Section IX.D of the paper for discussion.
