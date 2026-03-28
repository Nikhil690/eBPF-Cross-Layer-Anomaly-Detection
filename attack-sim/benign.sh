#!/usr/bin/env bash
# benign.sh — generate normal HTTP traffic as baseline
set -euo pipefail

TARGET="${1:-http://example.com}"
ROUNDS="${2:-30}"

echo "[*] Generating $ROUNDS benign HTTP requests to $TARGET"

for i in $(seq 1 "$ROUNDS"); do
    curl -s -o /dev/null -w "req=%{http_code} " "$TARGET" 2>/dev/null || true
    sleep "$(awk "BEGIN{printf \"%.1f\", 0.3 + rand()*0.7}")"
done

echo
echo "[*] Benign traffic complete ($ROUNDS requests)"
