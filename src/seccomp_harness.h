#ifndef EDR_SECCOMP_HARNESS_H
#define EDR_SECCOMP_HARNESS_H

#include <cstdint>
#include <string>
#include <vector>

struct HarnessCfg {
    bool gate_memfd = true;
    bool gate_mprotect_wx = true;
    bool gate_ptrace = true;
    bool gate_unshare = true;
    bool gate_connect = true;
    bool gate_execveat = true;
    bool gate_prctl_setname = true;
    bool default_allow_on_detach = true;
    bool log_allowed = true;
};

int harness_run(const std::vector<std::string> &argv, const HarnessCfg &cfg);

#endif