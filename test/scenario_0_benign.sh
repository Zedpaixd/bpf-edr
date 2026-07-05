#!/usr/bin/env bash
set -euo pipefail
H="$(cd "$(dirname "$0")" && pwd)"; R="$(cd "$H/.." && pwd)"; B="$R/build/chain_trigger"
[ -x "$B" ] || { mkdir -p "$R/build"; cc -O0 -g "$H/chain_trigger.c" -o "$B"; }
echo "=== Scenario 0: BENIGN baseline ==="
echo "stages    : fork + exec /bin/true (no suspicious categories)"
echo "expected  : risk stays at the benign floor (~1%). This is the"
echo "            control: normal process activity must NOT flag."
echo "watch      : tree row appears '* [pid] chain_trigger' near green."
echo
"$B" benign
echo
echo "PASS if the process never leaves green and never enters the watchlist."