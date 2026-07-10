#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; NC='\033[0m'
log(){ echo -e "${GRN}[setup]${NC} $*"; }
warn(){ echo -e "${YLW}[warn]${NC} $*"; }
die(){ echo -e "${RED}[fatal]${NC} $*"; exit 1; }

[ "$EUID" -eq 0 ] || die "run as root (sudo ./setup.sh)"

DISTRO_ID="unknown"
DISTRO_VER=""
if [ -r /etc/os-release ]; then
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_VER="${VERSION_ID:-}"
fi
log "distro: $DISTRO_ID $DISTRO_VER"

case "$DISTRO_ID" in
    ubuntu|debian|kali) ;;
    *) warn "untested distro '$DISTRO_ID'; assuming apt-compatible path" ;;
esac

if [ -r /proc/version ] && grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null; then
    log "WSL 2 environment detected"
else
    warn "not detected as WSL 2; script may still work but is untested off-WSL"
fi

export DEBIAN_FRONTEND=noninteractive

log "apt update"
apt-get update -qq

log "apt upgrade (keeping toolchain + kernel headers current)"
apt-get upgrade -y --no-install-recommends || warn "apt upgrade reported issues; continuing"

BASE_PKGS="build-essential clang llvm libbpf-dev cmake pkg-config zlib1g-dev libelf-dev git wget ca-certificates libcap-dev"

log "installing base toolchain"
apt-get install -y --no-install-recommends $BASE_PKGS

log "ensuring clang/llvm are the newest the distro offers"
apt-get install -y --only-upgrade clang llvm libbpf-dev 2>/dev/null || true

log "installing bpftool"
if apt-get install -y --no-install-recommends bpftool 2>/dev/null; then
    log "bpftool installed via apt"
else
    warn "'bpftool' package unavailable directly; trying distro-specific fallback"
    case "$DISTRO_ID" in
        ubuntu)
            apt-get install -y --no-install-recommends linux-tools-generic linux-tools-common || true
            ;;
        kali|debian)
            apt-get install -y --no-install-recommends linux-perf || true
            ;;
        *)
            apt-get install -y --no-install-recommends linux-perf || true
            ;;
    esac
fi

if ! command -v bpftool >/dev/null 2>&1; then
    KV=$(uname -r)
    for cand in \
        "/usr/sbin/bpftool" \
        "/usr/bin/bpftool" \
        "/usr/lib/linux-tools/${KV}/bpftool" \
        "/usr/lib/linux-tools-${KV%%-*}/bpftool"; do
        if [ -x "$cand" ]; then
            ln -sf "$cand" /usr/local/bin/bpftool
            log "linked bpftool from $cand"
            break
        fi
    done
fi

if ! command -v bpftool >/dev/null 2>&1; then
    BP=$(find /usr/lib/linux-tools* /usr/sbin /usr/bin -name bpftool 2>/dev/null | head -n1 || true)
    if [ -n "$BP" ]; then
        ln -sf "$BP" /usr/local/bin/bpftool
        log "linked bpftool from $BP"
    else
        die "bpftool not found. install manually: apt install bpftool"
    fi
fi

log "bpftool: $(bpftool version 2>&1 | head -n1 || echo unknown)"

log "checking BTF availability"
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    warn "/sys/kernel/btf/vmlinux missing."
    warn "on Windows PowerShell (admin) run: wsl --update"
    warn "then: wsl --shutdown ; and restart WSL."
    die "no BTF; cannot generate vmlinux.h"
fi

log "checking securityfs + BPF-LSM"
if [ ! -d /sys/kernel/security ] || [ ! -e /sys/kernel/security/lsm ]; then
    warn "securityfs not mounted; mounting at /sys/kernel/security"
    mount -t securityfs none /sys/kernel/security 2>/dev/null \
        || warn "securityfs mount failed; LSM + burst enforcement will be unavailable"
fi

LSM_ACTIVE=""
[ -r /sys/kernel/security/lsm ] && LSM_ACTIVE="$(cat /sys/kernel/security/lsm 2>/dev/null || true)"

if echo "$LSM_ACTIVE" | grep -qw bpf; then
    log "BPF-LSM active: $LSM_ACTIVE"
else
    warn "BPF-LSM NOT in the active LSM list: ${LSM_ACTIVE:-<unreadable>}"
    warn "kernel-side enforcement (LSM deny + burst auto-block) will not attach. On WSL 2:"
    warn "  1. Windows: edit  C:\\Users\\<you>\\.wslconfig , add under [wsl2]:"
    warn "       kernelCommandLine = lsm=landlock,lockdown,yama,loadpin,safesetid,integrity,selinux,apparmor,tomoyo,bpf"
    warn "     (your CONFIG_LSM string with ,bpf appended -- verify: cat /proc/cmdline)"
    warn "  2. PowerShell:  wsl --shutdown   (wait ~8s, reopen the distro)"
    warn "  3. re-run setup.sh; 'bpf' should appear in /sys/kernel/security/lsm"
    warn "continuing: detection + tracepoint sensing work; enforcement stays inert until bpf LSM is live."
fi

if ! grep -q "securityfs" /etc/fstab 2>/dev/null; then
    warn "to auto-mount securityfs at boot, add to /etc/fstab:"
    warn "  none  /sys/kernel/security  securityfs  defaults  0 0"
fi

log "checking tracefs mount"
if [ ! -d /sys/kernel/tracing/events/sched ]; then
    warn "tracefs not mounted at /sys/kernel/tracing"
    if mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null; then
        log "tracefs mounted"
    else
        warn "auto-mount failed; run manually: sudo mount -t tracefs nodev /sys/kernel/tracing"
    fi
fi

mkdir -p include external build

log "generating vmlinux.h from BTF"
bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h

log "downloading nlohmann json.hpp v3.11.3"
if [ ! -f include/json.hpp ]; then
    wget -q -O include/json.hpp https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp
fi

log "cloning FTXUI v5.0.0"
if [ ! -d external/ftxui ]; then
    git clone --depth=1 --branch v5.0.0 https://github.com/ArthurSonzogni/FTXUI external/ftxui
fi

log "setup complete. next: sudo make"