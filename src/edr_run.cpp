#include "seccomp_harness.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static void usage(const char *p) {
    std::printf("usage: %s [options] -- <binary> [args...]\n", p);
    std::printf("  analyst harness: launches <binary> under seccomp user-notify.\n");
    std::printf("  every gated syscall FREEZES mid-flight until you adjudicate it.\n\n");
    std::printf("  options (all gates on by default):\n");
    std::printf("    --no-memfd       don't gate memfd_create\n");
    std::printf("    --no-wx          don't gate mprotect W^X\n");
    std::printf("    --no-ptrace      don't gate ptrace\n");
    std::printf("    --no-unshare     don't gate unshare\n");
    std::printf("    --no-connect     don't gate connect\n");
    std::printf("    --no-execveat    don't gate execveat\n");
    std::printf("    --no-prctl       don't gate prctl PR_SET_NAME\n");
    std::printf("    --quiet-allowed  don't print allowed syscalls\n\n");
    std::printf("  example: sudo %s -- ./build/flood_trigger\n", p);
}

int main(int argc, char **argv) {
    HarnessCfg cfg;
    std::vector<std::string> target;
    int i = 1;
    for (; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--") { i++; break; }
        else if (a == "-h" || a == "--help") { usage(argv[0]); return 0; }
        else if (a == "--no-memfd") cfg.gate_memfd = false;
        else if (a == "--no-wx") cfg.gate_mprotect_wx = false;
        else if (a == "--no-ptrace") cfg.gate_ptrace = false;
        else if (a == "--no-unshare") cfg.gate_unshare = false;
        else if (a == "--no-connect") cfg.gate_connect = false;
        else if (a == "--no-execveat") cfg.gate_execveat = false;
        else if (a == "--no-prctl") cfg.gate_prctl_setname = false;
        else if (a == "--quiet-allowed") cfg.log_allowed = false;
        else { std::fprintf(stderr, "unknown option: %s\n", a.c_str()); usage(argv[0]); return 2; }
    }
    for (; i < argc; i++) target.push_back(argv[i]);
    if (target.empty()) { usage(argv[0]); return 2; }
    return harness_run(target, cfg);
}