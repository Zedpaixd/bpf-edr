#!/usr/bin/env bash
set -euo pipefail
H="$(cd "$(dirname "$0")" && pwd)"; R="$(cd "$H/.." && pwd)"; B="$R/build/chain_trigger"
[ -x "$B" ] || { mkdir -p "$R/build"; cc -O0 -g "$H/chain_trigger.c" -o "$B"; }
echo "=== Scenario 5: FULL kill-chain (+ C2, sustained) ==="
echo "stages    : memfd + W^X + rename + unshare + tcp-connect, then HOLD"
echo "            alive 12s so the dwell timer can complete."
echo "categories: X + M + E + P + C  (all five)"
echo "expected  : ~100%. Crosses kill_threshold and STAYS above it long"
echo "            enough to satisfy dwell -> the EDR issues kill(-pgid)."
echo
echo "IMPORTANT:"
echo "  * The EDR must have been running > warmup_sec (15s) or it will not"
echo "    mitigate. Start the EDR, wait ~20s, THEN run this."
echo "  * The worker calls setpgid(0,0), isolating itself in its own process"
echo "    group. The SIGKILL nukes ONLY the test lineage, never your shell."
echo
read -r -p "EDR running > 15s and ready? [enter to launch, Ctrl-C to abort] " _
"$B" full &
CT_PID=$!
echo "launched chain_trigger pid=$CT_PID; watch the EDR audit log for [KILL]."
wait "$CT_PID" 2>/dev/null || echo "(worker terminated -- expected if SIGKILL landed)"
echo
echo "PASS if the Audit Log shows a [KILL] pgid=... line and the worker dies"
echo "     early. FAIL (false-negative) if it runs the full 12s untouched."