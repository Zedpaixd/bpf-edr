#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BIN="$ROOT/build/trigger_suite"

if [ ! -x "$BIN" ]; then
    echo "[build] compiling trigger_suite"
    mkdir -p "$ROOT/build"
    cc -O0 -g "$HERE/trigger_suite.c" -o "$BIN"
fi

declare -A EXPECT=(
    [memfd]="EV_MEMFD_CREATE + EV_EXEC (memfd path)"
    [prctl]="EV_PRCTL_RENAME with MASQUERADE alert"
    [mprot]="EV_MPROTECT_WX (W|X detected)"
    [forkchain]="3 x EV_FORK, lineage backprop up 3 levels"
    [unshare]="EV_UNSHARE (namespace clone)"
)

echo "=== EDR validation harness ==="
echo "prerequisite: 'sudo ./build/edr rules.json' running in another terminal"
echo

for t in memfd prctl mprot forkchain unshare; do
    echo "[trigger] $t"
    echo "  expected: ${EXPECT[$t]}"
    "$BIN" "$t" || echo "  (trigger returned nonzero; may be permission-related)"
    echo "  observe the running EDR UI: matching event(s) should appear in the audit log"
    echo
    sleep 3
done

echo "=== validation complete ==="
echo "review the EDR audit log pane; each trigger should have produced its expected event class."