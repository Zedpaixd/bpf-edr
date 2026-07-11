#ifndef EDR_SECCOMP_FILTER_H
#define EDR_SECCOMP_FILTER_H

#include <string>
#include <vector>

struct SeccompGates {
    bool memfd = true;
    bool mprotect = true;
    bool ptrace = true;
    bool unshare = true;
    bool connect = true;
    bool execveat = true;
    bool prctl = true;
};

int seccomp_install_filter(const SeccompGates &gates);
int seccomp_send_fd(int sock, int fd);
int seccomp_recv_fd(int sock);
const char *seccomp_syscall_label(int nr);

#endif