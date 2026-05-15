#!/usr/bin/env bash
# Head-to-head benchmark: gossan-engine vs masscan.
#
# Both tools scan a configurable target range at the same rate; the
# script reports wall-time pps. Requires:
#   - sudo (raw sockets)
#   - masscan installed (sudo apt install masscan)
#   - the gossan binary built (cargo build --release -p gossan)
#
# Usage:
#   sudo ./scripts/vs_masscan.sh
#   sudo ./scripts/vs_masscan.sh 10.0.0.0/16   # custom range
#   sudo PORTS=1-1000 RATE=2000000 ./scripts/vs_masscan.sh
#
# What this is NOT: an apples-to-apples microbench (we measure full
# wall-time including DNS resolve / RX collection / output write).
# What this IS: the user-visible "did your scanner finish faster?"
# metric — which is what matters for actually beating masscan.

set -euo pipefail

RANGE="${1:-127.0.0.1/32}"
PORTS="${PORTS:-1-65535}"
RATE="${RATE:-1000000}"     # 1M pps default
INTERFACE="${INTERFACE:-lo}"

echo "=== gossan-engine vs masscan ==="
echo "Range:     $RANGE"
echo "Ports:     $PORTS"
echo "Rate:      $RATE pps"
echo "Interface: $INTERFACE"
echo

if ! command -v masscan >/dev/null; then
    echo "[!] masscan not installed. Install with: sudo apt install masscan"
    echo "    Skipping masscan run; reporting gossan numbers only."
    HAVE_MASSCAN=0
else
    HAVE_MASSCAN=1
fi

GOSSAN="$(dirname "$0")/../../../target/release/gossan"
if [[ ! -x "$GOSSAN" ]]; then
    echo "[!] gossan release binary not found at $GOSSAN"
    echo "    Build with: cargo build --release -p gossan"
    exit 1
fi

# ── Run masscan ──────────────────────────────────────────────────────
if [[ $HAVE_MASSCAN -eq 1 ]]; then
    echo "── masscan ──"
    MS_OUT=$(mktemp)
    /usr/bin/time -v masscan "$RANGE" -p"$PORTS" --rate="$RATE" \
        -e "$INTERFACE" -oG "$MS_OUT" 2>&1 | tee /tmp/masscan_run.log | tail -20
    MS_TIME=$(grep "Elapsed.*wall" /tmp/masscan_run.log | awk '{print $NF}')
    echo "masscan elapsed: $MS_TIME"
    echo
    rm -f "$MS_OUT"
fi

# ── Run gossan-engine ────────────────────────────────────────────────
echo "── gossan-engine ──"
GS_OUT=$(mktemp)
GOSSAN_TX_THREADS="${GOSSAN_TX_THREADS:-8}" \
    /usr/bin/time -v "$GOSSAN" ports "$RANGE" 2>&1 | tee /tmp/gossan_run.log | tail -20
GS_TIME=$(grep "Elapsed.*wall" /tmp/gossan_run.log | awk '{print $NF}')
echo "gossan elapsed: $GS_TIME"
rm -f "$GS_OUT"

echo
echo "=== Comparison ==="
[[ $HAVE_MASSCAN -eq 1 ]] && echo "masscan: $MS_TIME"
echo "gossan:  $GS_TIME"
