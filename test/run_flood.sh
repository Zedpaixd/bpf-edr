#!/usr/bin/env bash
set -euo pipefail
H="$(cd "$(dirname "$0")" && pwd)"; R="$(cd "$H/.." && pwd)"
BIN="$R/build/flood_trigger"
PROG="/tmp/flood_progress.txt"
ROUNDS="${1:-3}"

[ -x "$BIN" ] || { echo "[build] compiling flood_trigger"; mkdir -p "$R/build"; cc -O0 -g "$H/flood_trigger.c" -o "$BIN"; }

echo "=== FLOOD trigger (no inter-syscall delay) ==="
echo "rounds        : $ROUNDS  (each round ~41 monitored syscalls, all categories)"
echo "progress file : $PROG   (one line per syscall, written BEFORE it fires)"
echo
echo "PREREQUISITE : EDR running and showing ARMED (waited > warmup)."
echo
echo "HOW TO READ THE FREEZE:"
echo "  1. In a THIRD terminal:   tail -f $PROG"
echo "  2. Launch this flood."
echo "  3. When risk crosses the prompt threshold, the EDR SIGSTOPs the"
echo "     worker. The tail -f will STOP advancing at some number N."
echo "  4. That N is the exact syscall where execution halted. Resume (Y)"
echo "     in the EDR and the count resumes from N+1; Kill (K) and it never"
echo "     advances again."
echo
read -r -p "EDR ARMED and ready? [enter to flood, Ctrl-C to abort] " _
"$BIN" "$PROG" "$ROUNDS" &
FPID=$!
echo "flood launched (pid=$FPID). Progress: tail -f $PROG"
wait "$FPID" 2>/dev/null || echo "(worker terminated -- expected if you pressed K)"
echo
LAST=$(tail -n 1 "$PROG" 2>/dev/null || echo "<none>")
echo "last progress line written: $LAST"
echo "total lines: $(wc -l < "$PROG" 2>/dev/null || echo 0)"