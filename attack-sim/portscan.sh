#!/usr/bin/env bash
# portscan.sh — SYN scan simulation for eBPF-CLA evaluation
set -euo pipefail

TARGET="${1:-127.0.0.1}"
PORTS="${2:-1-1024}"

echo "[*] SYN scan → $TARGET ports $PORTS"
echo "[*] This will trigger ALERT events in ebpf-cla"

if command -v nmap &>/dev/null; then
    sudo nmap -sS -p "$PORTS" --min-rate 500 "$TARGET"
elif command -v hping3 &>/dev/null; then
    echo "[*] Falling back to hping3 (first 1024 ports)"
    for p in $(seq 1 1024); do
        hping3 -S -p "$p" -c 1 "$TARGET" 2>/dev/null &
    done
    wait
else
    echo "[*] No nmap/hping3; using /dev/tcp probes"
    for p in $(seq 1 1024); do
        (echo >/dev/tcp/"$TARGET"/"$p") 2>/dev/null &
    done
    wait
fi

echo "[*] Scan complete"
