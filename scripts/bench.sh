#!/usr/bin/env bash
# Cold-cache bench harness for production sensor deployments.
# Usage on sensor: sudo bash scripts/bench.sh /path/to/corpus.pcap

set -euo pipefail

PCAP="${1:?usage: bench.sh <file.pcap>}"
BIN="${BIN:-./target/release/pcap-slim}"

drop_caches() {
  if [[ -w /proc/sys/vm/drop_caches ]]; then
    echo 3 >/proc/sys/vm/drop_caches
  fi
}

run_once() {
  local label="$1"
  shift
  drop_caches || true
  /usr/bin/time -f "${label} elapsed=%e sec" "$BIN" "$@"
}

# Single-file in-place (writes to .pcap.tmp then rename)
TMP="${PCAP}.bench.tmp"
cp -f "$PCAP" "$TMP"

run_once "v2 default" --single "$TMP"
mv -f "${TMP%.pcap}.pcap.tmp" "$TMP" 2>/dev/null || true

cp -f "$PCAP" "$TMP"
run_once "v2 mmap" --single "$TMP" --mmap
rm -f "$TMP" "${TMP%.pcap}.pcap.tmp" 2>/dev/null || true

echo "Budgets (cold): 200MB ≤0.8s | 800MB ≤2.5s (no mmap) | 800MB ≤1.1s (mmap)"
