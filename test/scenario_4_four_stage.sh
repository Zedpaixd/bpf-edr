#!/usr/bin/env bash
set -euo pipefail
H="$(cd "$(dirname "$0")" && pwd)"; R="$(cd "$H/.." && pwd)"; B="$R/build/chain_trigger"
[ -x "$B" ] || { mkdir -p "$R/build"; cc -O0 -g "$H/chain_trigger.c" -o "$B"; }
echo "=== Scenario 4: FOUR-stage chain (+ privilege) ==="
echo "stages    : memfd + W^X + rename + unshare(CLONE_NEWUSER)"
echo "categories: EXECUTION (X) + MEMORY (M) + EVASION (E) + PRIVILEGE (P)"
echo "expected  : ~99%. Deep corroboration. Still short-lived, so it should"
echo "            spike into the red and then exit before the dwell window."
echo "watch      : st=XMEP, top of the Watchlist, retained as a dead"
echo "            forensic node after exit (peak >= 40% is never GC'd)."
echo
"$B" four
echo
echo "PASS if risk is near-max AND the dead node persists in tree + watchlist."