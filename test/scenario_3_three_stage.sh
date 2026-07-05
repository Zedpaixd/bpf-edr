#!/usr/bin/env bash
set -euo pipefail
H="$(cd "$(dirname "$0")" && pwd)"; R="$(cd "$H/.." && pwd)"; B="$R/build/chain_trigger"
[ -x "$B" ] || { mkdir -p "$R/build"; cc -O0 -g "$H/chain_trigger.c" -o "$B"; }
echo "=== Scenario 3: THREE-stage chain (+ masquerade) ==="
echo "stages    : memfd + W^X + prctl rename to 'kworker/0:9H'"
echo "categories: EXECUTION (X) + MEMORY (M) + EVASION (E)"
echo "expected  : ~90%, right at the kill boundary. Process exits fast so"
echo "            the dwell timer never completes -> flagged but NOT killed."
echo "watch      : st=XM E, red in the tree, Masquerade Log shows"
echo "            'chain_trigger' -> 'kworker/0:9H' [!] in magenta."
echo
"$B" three
echo
echo "PASS if risk is high (>75%) AND no SIGKILL fires (short-lived, no dwell)."