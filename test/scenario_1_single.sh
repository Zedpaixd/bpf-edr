#!/usr/bin/env bash
set -euo pipefail
H="$(cd "$(dirname "$0")" && pwd)"; R="$(cd "$H/.." && pwd)"; B="$R/build/chain_trigger"
[ -x "$B" ] || { mkdir -p "$R/build"; cc -O0 -g "$H/chain_trigger.c" -o "$B"; }
echo "=== Scenario 1: SINGLE weak signal (W^X only) ==="
echo "stages    : one mprotect(PROT_WRITE|PROT_EXEC) then restore"
echo "category  : MEMORY (M)"
echo "expected  : ~3-4%. A lone W^X page is exactly the JIT / interpreter"
echo "            false-positive we deliberately do NOT escalate on."
echo "watch      : one category active (st=M), risk low, no watchlist entry."
echo
"$B" single
echo
echo "PASS if risk stays well below 20% (single category cannot corroborate)."