#include "seccomp_filter.h"
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif

static long seccomp_raw(unsigned int op, unsigned int flags, void *args) {
    return syscall(__NR_seccomp, op, flags, args);
}

int seccomp_install_filter(const SeccompGates &gates) {
    std::vector<struct sock_filter> prog;
    auto emit = [&](struct sock_filter f) { prog.push_back(f); };

    emit(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)));
    emit(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
    emit(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    emit(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)));

    struct G { bool on; int nr; };
    G gs[] = {
        { gates.memfd,    __NR_memfd_create },
        { gates.mprotect, __NR_mprotect },
        { gates.ptrace,   __NR_ptrace },
        { gates.unshare,  __NR_unshare },
        { gates.connect,  __NR_connect },
        { gates.execveat, __NR_execveat },
        { gates.prctl,    __NR_prctl },
    };
    for (auto &g : gs) {
        if (!g.on) continue;
        emit(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)g.nr, 0, 1));
        emit(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF));
    }
    emit(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    struct sock_fprog fprog;
    fprog.len = (unsigned short)prog.size();
    fprog.filter = prog.data();

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        std::perror("prctl(NO_NEW_PRIVS)");
        return -1;
    }
    long fd = seccomp_raw(SECCOMP_SET_MODE_FILTER,
                          SECCOMP_FILTER_FLAG_NEW_LISTENER, &fprog);
    if (fd < 0) {
        std::perror("seccomp(SET_MODE_FILTER, NEW_LISTENER)");
        return -1;
    }
    return (int)fd;
}

int seccomp_send_fd(int sock, int fd) {
    struct msghdr msg = {};
    char dummy = 'x';
    struct iovec io = { &dummy, 1 };
    char cbuf[CMSG_SPACE(sizeof(int))];
    std::memset(cbuf, 0, sizeof(cbuf));
    msg.msg_iov = &io; msg.msg_iovlen = 1;
    msg.msg_control = cbuf; msg.msg_controllen = sizeof(cbuf);
    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_SOCKET; cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(cm), &fd, sizeof(int));
    return sendmsg(sock, &msg, 0) < 0 ? -1 : 0;
}

int seccomp_recv_fd(int sock) {
    struct msghdr msg = {};
    char dummy;
    struct iovec io = { &dummy, 1 };
    char cbuf[CMSG_SPACE(sizeof(int))];
    msg.msg_iov = &io; msg.msg_iovlen = 1;
    msg.msg_control = cbuf; msg.msg_controllen = sizeof(cbuf);
    if (recvmsg(sock, &msg, 0) < 0) return -1;
    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
    if (!cm || cm->cmsg_type != SCM_RIGHTS) return -1;
    int fd; std::memcpy(&fd, CMSG_DATA(cm), sizeof(int));
    return fd;
}

const char *seccomp_syscall_label(int nr) {
    switch (nr) {
        case __NR_memfd_create: return "memfd_create (fileless exec)";
        case __NR_mprotect:     return "mprotect (memory W^X)";
        case __NR_ptrace:       return "ptrace (process tampering)";
        case __NR_unshare:      return "unshare (namespace escape)";
        case __NR_connect:      return "connect (outbound C2)";
        case __NR_execveat:     return "execveat (exec from fd)";
        case __NR_prctl:        return "prctl (rename/masquerade)";
    }
    return "syscall";
}