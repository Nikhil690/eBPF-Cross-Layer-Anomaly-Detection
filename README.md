# eBPF-Powered Cross-Layer Anomaly Detection

**A Unified Kernel-Space Security Monitoring Framework for Linux Systems**

> Nikhil Jangid · Nikhil Kumar Rajput · Sahil Pathak
> Ramanujan College, University of Delhi
> Target venue: IEEE TNSM

---

## What This Is

An intrusion detection system that correlates signals from **three kernel layers simultaneously** using eBPF — without any userspace packet copies or kernel modifications.

| Layer | Hook | What It Captures |
|---|---|---|
| L4 Network | XDP (ingress) | 5-tuple, TCP flags, packet rates, inter-arrival time |
| L4 Correlation | TC cls_bpf (egress) | Socket cookie join, corr-window assembly |
| Process/Kernel | Tracepoint `sys_enter_connect` | Connect rate, PID, UID, comm |

**Key mechanism:** `socket_cookie` (`bpf_get_socket_cookie()`) is used as a zero-copy kernel-resident join key that links XDP events → TC events → syscall events without any userspace intermediary.

**Output:** Corr-records assembled in kernel → ring buffer → Go userspace → anomaly scorer.

---

## Measured Results (Linux 6.8, 2026-03-28)

### Detection Performance (flow-level, 1,530 flows, 6 attack categories)

| Category | Flows | Recall |
|---|---|---|
| Port scan | 699 | **99.6%** |
| SYN flood | 610 | **99.5%** |
| Cryptomining C2 | 43 | **93.0%** |
| Privilege escalation | 24 | **87.5%** |
| Rootkit beaconing | 28 | **85.7%** |
| Data exfiltration | 17 | **82.4%** |

| Detector | Precision | Recall | F1 |
|---|---|---|---|
| Rule-based (pkt+windows) | 0.930 | 0.987 | **0.957** |
| z-score online (event-level) | 0.950 | 0.038 | 0.073 |
| Isolation Forest | 0.792 | 0.030 | 0.057 |
| OC-SVM | 0.680 | 0.012 | 0.024 |

### Performance Overhead

| Component | Metric |
|---|---|
| XDP `xdp_flow_monitor` | ~1,970 ns/call |
| TC `tc_correlate` | ~4,985 ns/call |
| TP `trace_connect` | ~3,104 ns/call |
| Per-packet kernel overhead (XDP+TC) | ~4 µs |
| BPF map memory | 43.1 MB |
| Userspace RSS | 6.96 MB |
| Userspace CPU (idle) | 0.3% |

---

## Repository Layout

```
ebpf-cla/
├── bpf/
│   ├── common.h           Shared structs, map definitions, helper inlines
│   ├── xdp.c              XDP ingress: 5-tuple → flow_stats_map
│   ├── tc.c               TC egress: socket cookie join → corr_window_map → ring_events
│   ├── tracepoint.c       sys_enter_connect: proc_state → corr_window_map
│   └── vmlinux.h          BTF type dump (CO-RE portability)
│
├── main.go                Entry point, ring buffer + swept-flow consumer, --csv/--label flags
├── loader.go              cilium/ebpf lifecycle: load, attach XDP/TCX/TP, map sharing, sweeper
├── correlator.go          CorrRecord parsing, tcRecordToCorrRecord, ExtractFeatures
├── detector.go            OnlineStats (Welford), AnomalyScore, warmup guard (n<50)
│
├── attack-sim/
│   ├── benign.sh          Normal HTTP traffic baseline (curl)
│   ├── portscan.sh        TCP SYN scan (nmap / /dev/tcp fallback)
│   ├── synflood.sh        Rapid serial TCP connects to one host
│   ├── privesc_sim.sh     execve burst + C2 connection pattern
│   ├── exfil_sim.sh       Large-payload HTTP POSTs
│   ├── cryptomining_sim.sh  Stratum pool reconnects (ports 3333/4444/14444/45700)
│   └── rootkit_sim.sh     Port-knock sequence + periodic beaconing
│
├── results/
│   ├── collect_sessions.sh      Per-phase labelled data collection (uses --csv/--label)
│   ├── continuous_eval.sh       Multi-phase collection, one process per phase
│   ├── single_session_eval.sh   Single continuous process, timestamp labelling
│   ├── raw/
│   │   ├── sessions_merged.csv        5,361 events, 7 classes (primary dataset)
│   │   ├── single_20260328_104918.csv 13,258 events, single-process session
│   │   └── *.csv                      Per-run raw dumps
│   └── analysis/
│       └── evaluate.py          Flow-level sklearn evaluator (IF + OC-SVM + rule + ensemble)
│
├── *_bpfel.go / *_bpfel.o    bpf2go-generated Go skeletons + compiled BPF objects (little-endian)
├── *_bpfeb.go / *_bpfeb.o    bpf2go-generated (big-endian, unused on x86)
├── go.mod / go.sum
├── Makefile
└── CLAUDE.md              Project context + session handoff notes
```

---

## How It Works

### BPF Map Architecture

```
┌─────────────────┐   ┌─────────────────┐   ┌──────────────────┐
│   XDP (ingress) │   │   TC (egress)   │   │  Tracepoint (TP) │
│                 │   │                 │   │  sys_enter_connect│
│ flow_stats_map  │──►│ cookie_map      │   │  proc_state_map   │
│ (LRU_HASH)      │   │ corr_window_map │◄──│  (HASH)           │
│ key: 5-tuple    │   │ ring_events     │   │  key: PID         │
└─────────────────┘   └────────┬────────┘   └──────────────────┘
                               │ ring buffer
                               ▼
                    ┌──────────────────────┐
                    │   Go userspace       │
                    │   ring buffer reader │
                    │   + map sweeper(20ms)│
                    │   → OnlineStats      │
                    │   → AnomalyScore     │
                    │   → CSV / alerts     │
                    └──────────────────────┘
```

### Correlation Algorithm

Every TC egress packet:
1. Get `socket_cookie` via `bpf_get_socket_cookie(skb)` (only non-zero on egress)
2. Reverse 5-tuple (egress→ingress perspective) to look up `flow_stats_map` from XDP
3. Upsert `corr_window_map[cookie]` with XDP stats + layer coverage bit
4. If window age > 5 ms **or** all layers seen → emit to `ring_events`, delete entry

**Userspace sweeper** (20 ms goroutine): iterates `corr_window_map`, emits entries older than 5 ms directly. This is essential — short-lived connections (port scans) close their sockets before the kernel-side TC check fires again.

### Anomaly Scorer

Welford's online algorithm tracks per-feature mean + variance incrementally. `AnomalyScore` returns the Euclidean z-score distance across 9 features:

```
pkt_count, byte_count, syn_count, rst_count, syn_ratio,
duration, pkt_rate, layer_coverage, connect_rate
```

A warmup guard (`n < 50`) suppresses scoring during the first 50 events to avoid cold-start false positives.

---

## Requirements

| Requirement | Version |
|---|---|
| Linux kernel | **≥ 5.8** (ring buffer; hard floor) |
| clang | ≥ 14 (`-target bpf -O2 -g` for BTF) |
| Go | ≥ 1.21 |
| libbpf-dev | for `bpf_helpers.h` |
| Capabilities | `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON` |

Tested on: **Linux 6.8.0-106-generic**, clang 18, Go 1.25.

---

## Build & Run

```bash
# 1. Generate vmlinux.h (if not present)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

# 2. Compile eBPF C → Go skeletons + build binary
make build
# equivalent to:
#   go generate ./...   (runs bpf2go for xdp.c, tc.c, tracepoint.c)
#   go build -o ebpf-cla .

# 3. Run (requires root / CAP_BPF + CAP_NET_ADMIN)
sudo ./ebpf-cla ens3

# With CSV output for evaluation
sudo ./ebpf-cla ens3 --csv results/raw/out.csv --label benign

# Available flags
#   <iface>          network interface to monitor (default: eth0)
#   --csv <path>     append every event to CSV
#   --label <name>   label written to the csv 'label' column
```

---

## Evaluation

### Quick single-attack test

```bash
# Terminal 1 — start monitor
sudo ./ebpf-cla ens3

# Terminal 2 — port scan
bash attack-sim/portscan.sh <target-ip>
# or synflood:
bash attack-sim/synflood.sh <target-ip>
```

### Full labelled dataset collection

```bash
# Collect all 6 attack categories (takes ~5 min)
sudo bash results/collect_sessions.sh ens3

# Run sklearn evaluation on the output
python3 results/analysis/evaluate.py results/raw/sessions_merged.csv
```

### Single continuous session (most realistic)

```bash
# Builds benign baseline then injects each attack in sequence
sudo bash results/single_session_eval.sh ens3
```

### CSV schema

```
timestamp, label, score, layers, syn_count, rst_count,
pkt_count, byte_count, pkt_rate, layer_coverage, connect_rate, cookie
```

`layers` is a 4-character mask: `X`=XDP seen, `T`=TC seen, `S`=syscall seen, `U`=uprobe seen (`.` = absent). Example: `XT..` = XDP + TC only.

---

## Known Limitations & Future Work

| Issue | Detail |
|---|---|
| sklearn models low recall | Benign short connections (curl) overlap with attack short connections at per-flow level; fix: session-window (1 s) feature aggregation |
| Proc layer rarely joins | `skc_cookie` is 0 at tracepoint time (socket hasn't been through TC yet); correlation requires TC to run first |
| No uprobe layer yet | TLS uprobe on `libssl.so` is designed but not implemented (LAYER_UPROBE bit reserved) |
| Online stats per-process | Each binary restart resets Welford state; a persistent baseline store would improve recall across restarts |
| Map sweeper is userspace | For sub-millisecond latency requirements, migrate to BPF timer (kernel ≥ 5.15) |

---

## BPF Map Reference

| Map | Type | Key | Value | Owner |
|---|---|---|---|---|
| `flow_stats_map` | LRU_HASH 65536 | `cla_flow_key` (5-tuple) | `cla_flow_stats` | XDP (shared with TC) |
| `cookie_map` | HASH 65536 | `cla_flow_key` | `u64 cookie` | TC |
| `corr_window_map` | LRU_HASH 65536 | `u64 cookie` | `cla_corr_record` | TC (shared with TP) |
| `ring_events` | RINGBUF 16 MB | — | `cla_corr_record` | TC (shared with TP) |
| `proc_state_map` | HASH 4096 | `u32 pid` | `cla_proc_state` | TP |

---

## Paper Status

| Section | Status | Action |
|---|---|---|
| Abstract | needs update | Replace fabricated numbers with F1=0.957, overhead <5 µs |
| I. Introduction | solid | Add pre-solution gap sentence |
| II. Background | needs rewrite | Too close to source phrasing |
| III. Related Work | needs rewrite | Each paragraph must end with gap our system addresses |
| IV. System Design | solid | Fix broken Fig. ?? reference |
| V. Methodology | incomplete | Add grid search / ensemble weight description |
| VIII. Results | replace entirely | Use numbers from this README |
| Fig. 1 caption | wrong | "upper-left" not "upper-right" |
| Architecture figure | missing | Generate XDP→TC→TP→ring→sweeper→detector diagram |
