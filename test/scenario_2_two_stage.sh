#!/usr/bin/env bash
set -euo pipefail
H="$(cd "$(dirname "$0")" && pwd)"; R="$(cd "$H/.." && pwd)"; B="$R/build/chain_trigger"
[ -x "$B" ] || { mkdir -p "$R/build"; cc -O0 -g "$H/chain_trigger.c" -o "$B"; }
echo "=== Scenario 2: TWO-stage chain (fileless exec + W^X) ==="
echo "stages    : memfd_create + mprotect W^X on one process"
echo "categories: EXECUTION (X) + MEMORY (M)"
echo "expected  : ~35%. First point where corroboration engages -- two"
echo "            distinct kill-chain stages on the same lineage."
echo "watch      : st=XM, process enters the Watchlist (peak >= 40% may"
echo "            or may not be crossed; it hovers near the boundary)."
echo
"$B" two
echo
echo "PASS if risk jumps clearly above the single-stage case but stays sub-alarm."