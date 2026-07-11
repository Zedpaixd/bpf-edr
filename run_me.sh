#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD="$ROOT/build"
BIN="$ROOT/bin"
TEST="$ROOT/test"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'; NC='\033[0m'; B='\033[1m'
say(){ echo -e "${GRN}[run_me]${NC} $*"; }
warn(){ echo -e "${YLW}[warn]${NC} $*"; }
err(){ echo -e "${RED}[error]${NC} $*"; }
hdr(){ echo -e "\n${B}${CYN}== $* ==${NC}"; }

REAL_USER="${SUDO_USER:-$USER}"
REAL_UID="$(id -u "$REAL_USER" 2>/dev/null || echo 0)"
REAL_GID="$(id -g "$REAL_USER" 2>/dev/null || echo 0)"

need_root_reexec() {
    if [ "$EUID" -ne 0 ]; then
        warn "this action needs root; re-running with sudo..."
        exec sudo -E "$0" "$@"
    fi
}

fix_build_ownership() {
    if [ -d "$BUILD" ]; then
        local owner
        owner="$(stat -c '%U' "$BUILD" 2>/dev/null || echo unknown)"
        if [ "$owner" = "root" ] && [ "$REAL_USER" != "root" ]; then
            warn "build/ is root-owned; returning it to $REAL_USER"
            chown -R "$REAL_UID:$REAL_GID" "$BUILD" 2>/dev/null || true
        fi
    fi
}

usage() {
    cat <<EOF
${B}run_me.sh${NC} — build, check, and run the eBPF EDR + seccomp harness

${B}USAGE${NC}
  ./run_me.sh <command>

${B}COMMANDS${NC}
  --help          show this help
  --check-env     verify the machine can run everything (BTF, BPF-LSM, seccomp,
                  tracefs, toolchain) without changing anything
  --setup         full first-time setup: toolchain, deps, vmlinux.h, /etc/edr,
                  then build the EDR, the debug harness, and the test binaries
  --recompile     rebuild the EDR and test binaries (no deps or env checks)
  --edr           build (if needed) and launch the EDR monitor. auto-elevates to
                  root and fixes build/ ownership if a prior sudo build broke it
  --supervise     the demo: launch the EDR, then run the flood UNDER seccomp
                  supervision so every risky syscall freezes for approval
  --clean         remove build/, bin/, and generated artifacts (keeps /etc/edr)

${B}NOTES${NC}
  - Test binaries build to ${B}bin/${NC}, never to build/, so they don't collide
    with the CMake tree or need root to compile.
  - --edr and --supervise elevate themselves with sudo as needed.
EOF
}

# ---------- environment check ----------
cmd_check_env() {
    hdr "environment check (read-only)"
    local ok=1

    echo -e "${B}kernel & platform${NC}"
    echo "  kernel: $(uname -r)"
    if grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null; then
        echo -e "  WSL2:   ${GRN}yes${NC}"
    else
        echo -e "  WSL2:   ${YLW}not detected${NC} (fine if bare Linux)"
    fi

    echo -e "${B}BTF (needed to build BPF)${NC}"
    if [ -f /sys/kernel/btf/vmlinux ]; then echo -e "  ${GRN}present${NC}"; else echo -e "  ${RED}MISSING${NC} — run: wsl --update (Windows), then restart WSL"; ok=0; fi

    echo -e "${B}BPF-LSM (needed for kernel enforcement)${NC}"
    local lsm=""
    [ -r /sys/kernel/security/lsm ] && lsm="$(cat /sys/kernel/security/lsm 2>/dev/null)"
    if echo "$lsm" | grep -qw bpf; then
        echo -e "  ${GRN}active${NC}: $lsm"
    else
        echo -e "  ${YLW}not active${NC}: ${lsm:-<unreadable>}"
        echo -e "    enforcement (LSM deny + burst block) will be inert."
        echo -e "    add ',bpf' to CONFIG_LSM via .wslconfig kernelCommandLine, restart WSL."
    fi

    echo -e "${B}seccomp user-notify (needed for supervised harness)${NC}"
    if grep -q CONFIG_SECCOMP_FILTER=y /boot/config-"$(uname -r)" 2>/dev/null \
       || { [ -r /proc/config.gz ] && zcat /proc/config.gz 2>/dev/null | grep -q CONFIG_SECCOMP_FILTER=y; }; then
        echo -e "  ${GRN}CONFIG_SECCOMP_FILTER=y${NC}"
    else
        echo -e "  ${YLW}could not confirm${NC} CONFIG_SECCOMP_FILTER (kernel config not readable)"
        echo -e "    the harness may still work; this check is best-effort."
    fi

    echo -e "${B}tracefs (needed for tracepoints)${NC}"
    if [ -d /sys/kernel/tracing/events/sched ]; then echo -e "  ${GRN}mounted${NC}"; else echo -e "  ${YLW}not mounted${NC} — will auto-mount at run (needs root)"; fi

    echo -e "${B}toolchain${NC}"
    for t in clang bpftool cmake gcc g++; do
        if command -v "$t" >/dev/null 2>&1; then echo -e "  ${GRN}$t${NC}"; else echo -e "  ${RED}$t MISSING${NC} — run ./run_me.sh --setup"; ok=0; fi
    done

    echo -e "${B}build artifacts${NC}"
    [ -x "$BUILD/edr" ] && echo -e "  ${GRN}build/edr present${NC}" || echo -e "  ${YLW}build/edr not built${NC} — run ./run_me.sh --setup or --edr"
    [ -x "$BIN/flood_trigger" ] && echo -e "  ${GRN}bin/flood_trigger present${NC}" || echo -e "  ${YLW}bin/flood_trigger not built${NC}"

    echo
    if [ "$ok" -eq 1 ]; then say "core requirements look OK."; else warn "some requirements missing — see above."; fi
}

# ---------- build helpers ----------
build_edr() {
    hdr "building EDR (cmake)"
    need_root_reexec --edr-internal-build
    fix_build_ownership
    mkdir -p "$BUILD"
    ( cd "$BUILD" && cmake .. >/dev/null && make -j"$(nproc)" ) || { err "EDR build failed"; return 1; }
    say "EDR built: $BUILD/edr"
    # hand ownership back so future non-root test builds don't break
    if [ "$REAL_USER" != "root" ]; then chown -R "$REAL_UID:$REAL_GID" "$BUILD" 2>/dev/null || true; fi
}

build_tests() {
    hdr "building test binaries (standalone -> bin/)"
    mkdir -p "$BIN"
    local made=0
    if [ -f "$TEST/flood_trigger.c" ]; then
        gcc -O2 -o "$BIN/flood_trigger" "$TEST/flood_trigger.c" && { say "built bin/flood_trigger"; made=1; }
    fi
    if [ -f "$TEST/flood_trigger_noninteractive.c" ]; then
        gcc -O2 -o "$BIN/flood_ni" "$TEST/flood_trigger_noninteractive.c" && { say "built bin/flood_ni"; made=1; }
    fi
    if [ "$made" -eq 0 ]; then warn "no test .c files found in $TEST (expected flood_trigger.c)"; fi
    if [ "$REAL_USER" != "root" ] && [ "$EUID" -eq 0 ]; then chown -R "$REAL_UID:$REAL_GID" "$BIN" 2>/dev/null || true; fi
}

# ---------- setup ----------
cmd_setup() {
    need_root_reexec --setup
    hdr "full setup"
    if [ -x "$ROOT/setup.sh" ]; then
        "$ROOT/setup.sh" || { err "setup.sh failed"; exit 1; }
    else
        warn "setup.sh not found; skipping toolchain/deps step"
    fi
    build_edr || exit 1
    build_tests
    say "setup complete."
    echo -e "  run the monitor:      ${B}./run_me.sh --edr${NC}"
    echo -e "  run the demo:         ${B}./run_me.sh --supervise${NC}"
}

# ---------- run edr ----------
cmd_edr() {
    need_root_reexec --edr
    fix_build_ownership
    [ -x "$BUILD/edr" ] || build_edr || exit 1
    hdr "launching EDR monitor"
    say "keys inside: S=supervise a process, R=reputation, ?=help, q=quit"
    cd "$ROOT"
    exec "$BUILD/edr" "$ROOT/rules.json"
}

# ---------- supervise demo ----------
cmd_supervise() {
    need_root_reexec --supervise
    fix_build_ownership
    [ -x "$BUILD/edr" ] || build_edr || exit 1
    [ -x "$BIN/flood_ni" ] || [ -x "$BIN/flood_trigger" ] || build_tests

    local target=""
    if [ -x "$BIN/flood_ni" ]; then target="$BIN/flood_ni"; else target="$BIN/flood_trigger"; fi

    hdr "supervised demo"
    say "the EDR will launch. Inside it, press ${B}S${NC} and type:"
    echo -e "     ${B}$target /tmp/edr_demo.txt 1${NC}"
    say "each risky syscall from the flood will FREEZE for your approval,"
    say "showing the eBPF confidence current -> predicted."
    echo
    say "press enter to launch the EDR..."
    read -r _ </dev/tty
    cd "$ROOT"
    rm -f /tmp/edr_demo.txt
    exec "$BUILD/edr" "$ROOT/rules.json"
}

# ---------- recompile (fast rebuild, no env/dep work) ----------
cmd_recompile() {
    need_root_reexec --recompile
    hdr "recompile (code only)"
    fix_build_ownership
    if [ ! -f "$BUILD/CMakeCache.txt" ]; then
        warn "no cmake cache yet; configuring fresh"
        mkdir -p "$BUILD"
        ( cd "$BUILD" && cmake .. >/dev/null ) || { err "cmake configure failed"; exit 1; }
    fi
    ( cd "$BUILD" && make -j"$(nproc)" ) || { err "EDR build failed"; exit 1; }
    say "EDR rebuilt: $BUILD/edr"
    build_tests
    if [ "$REAL_USER" != "root" ]; then
        chown -R "$REAL_UID:$REAL_GID" "$BUILD" 2>/dev/null || true
        chown -R "$REAL_UID:$REAL_GID" "$BIN" 2>/dev/null || true
    fi
    say "recompile complete."
}

# ---------- clean ----------
cmd_clean() {
    hdr "clean"
    fix_build_ownership
    rm -rf "$BUILD" "$BIN"
    say "removed build/ and bin/ (kept /etc/edr and generated include/)."
    warn "to also remove the reputation store: sudo rm -rf /etc/edr"
}

# ---------- dispatch ----------
case "${1:-}" in
    --help|-h|"") usage ;;
    --check-env)  cmd_check_env ;;
    --setup)      cmd_setup ;;
    --recompile)  cmd_recompile ;;
    --edr)        cmd_edr ;;
    --edr-internal-build) build_edr ;;
    --supervise)  cmd_supervise ;;
    --clean)      cmd_clean ;;
    *) err "unknown command: $1"; echo; usage; exit 2 ;;
esac