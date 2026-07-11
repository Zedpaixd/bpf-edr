#include "seccomp_harness.h"
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <sched.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#ifndef SECCOMP_GET_NOTIF_SIZES
#define SECCOMP_GET_NOTIF_SIZES 3
#endif
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif
#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif
#ifndef SECCOMP_IOCTL_NOTIF_RECV
#define SECCOMP_IOCTL_NOTIF_RECV _IOWR('!', 0, struct seccomp_notif)
#endif
#ifndef SECCOMP_IOCTL_NOTIF_SEND
#define SECCOMP_IOCTL_NOTIF_SEND _IOWR('!', 1, struct seccomp_notif_resp)
#endif
#ifndef PR_SET_NAME
#define PR_SET_NAME 15
#endif

static const char *RED="\033[0;31m", *GRN="\033[0;32m", *YLW="\033[1;33m",
                  *CYN="\033[0;36m", *MAG="\033[0;35m", *NC="\033[0m", *BOLD="\033[1m";

static long seccomp_syscall(unsigned int op, unsigned int flags, void *args) {
    return syscall(__NR_seccomp, op, flags, args);
}

static int install_filter_and_get_fd(const HarnessCfg &cfg) {
    std::vector<struct sock_filter> prog;
    auto emit = [&](struct sock_filter f) { prog.push_back(f); };

    emit(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)));
    emit(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
    emit(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    emit(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)));

    struct Gate { bool on; int nr; };
    Gate gates[] = {
        { cfg.gate_memfd,        __NR_memfd_create },
        { cfg.gate_mprotect_wx,  __NR_mprotect },
        { cfg.gate_ptrace,       __NR_ptrace },
        { cfg.gate_unshare,      __NR_unshare },
        { cfg.gate_connect,      __NR_connect },
        { cfg.gate_execveat,     __NR_execveat },
        { cfg.gate_prctl_setname,__NR_prctl },
    };
    for (auto &g : gates) {
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
    long fd = seccomp_syscall(SECCOMP_SET_MODE_FILTER,
                              SECCOMP_FILTER_FLAG_NEW_LISTENER, &fprog);
    if (fd < 0) {
        std::perror("seccomp(SET_MODE_FILTER, NEW_LISTENER)");
        return -1;
    }
    return (int)fd;
}

static int send_fd_over(int sock, int fd) {
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

static int recv_fd_over(int sock) {
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

static const char *syscall_name(int nr) {
    switch (nr) {
        case __NR_memfd_create: return "memfd_create (fileless exec)";
        case __NR_mprotect:     return "mprotect (memory permission change)";
        case __NR_ptrace:       return "ptrace (process tampering)";
        case __NR_unshare:      return "unshare (namespace/isolation)";
        case __NR_connect:      return "connect (outbound network)";
        case __NR_execveat:     return "execveat (exec, possibly from memfd)";
        case __NR_prctl:        return "prctl (possible PR_SET_NAME masquerade)";
    }
    return "syscall";
}

static char read_key_blocking() {
    int tty = ::open("/dev/tty", O_RDONLY);
    if (tty < 0) tty = STDIN_FILENO;
    struct termios old, raw;
    tcgetattr(tty, &old);
    raw = old;
    raw.c_lflag &= ~(ICANON | ECHO);
    raw.c_cc[VMIN] = 1; raw.c_cc[VTIME] = 0;
    tcsetattr(tty, TCSANOW, &raw);
    char c = 0;
    ssize_t n = read(tty, &c, 1);
    tcsetattr(tty, TCSANOW, &old);
    if (tty != STDIN_FILENO) ::close(tty);
    if (n <= 0) return 0;
    return c;
}

static std::string ts_now() {
    std::time_t t = std::time(nullptr);
    std::tm tmv; localtime_r(&t, &tmv);
    char b[16];
    std::snprintf(b, sizeof(b), "%02d:%02d:%02d",
        tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    return b;
}

static int supervisor_loop(int notify_fd, pid_t child, const HarnessCfg &cfg) {
    struct seccomp_notif_sizes sizes;
    if (seccomp_syscall(SECCOMP_GET_NOTIF_SIZES, 0, &sizes) < 0) {
        std::perror("seccomp(GET_NOTIF_SIZES)");
        return 1;
    }
    struct seccomp_notif *req = (struct seccomp_notif *)std::calloc(1, sizes.seccomp_notif);
    struct seccomp_notif_resp *resp =
        (struct seccomp_notif_resp *)std::calloc(1, sizes.seccomp_notif_resp);
    if (!req || !resp) { std::fprintf(stderr, "calloc notif\n"); return 1; }

    long gated = 0, allowed = 0, denied = 0;

    std::printf("%s%s[edr-run]%s supervising pid=%d — each gated syscall FREEZES until you decide.\n",
                BOLD, CYN, NC, child);
    std::printf("        keys:  %sy%s allow   %sn%s deny(EPERM)   %sk%s kill   %sA%s allow-all-remaining\n\n",
                GRN, NC, YLW, NC, RED, NC, MAG, NC);
    std::fflush(stdout);

    bool allow_all = false;

    for (;;) {
        std::memset(req, 0, sizes.seccomp_notif);
        if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, req) != 0) {
            if (errno == EINTR) continue;
            break;
        }
        int nr = req->data.nr;
        gated++;

        bool wx = false;
        if (nr == __NR_mprotect) {
            unsigned long prot = req->data.args[2];
            wx = (prot & 0x2) && (prot & 0x4);
            if (!wx) {
                std::memset(resp, 0, sizes.seccomp_notif_resp);
                resp->id = req->id;
                resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, resp);
                continue;
            }
        }
        if (nr == __NR_prctl) {
            if (req->data.args[0] != PR_SET_NAME) {
                std::memset(resp, 0, sizes.seccomp_notif_resp);
                resp->id = req->id;
                resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, resp);
                continue;
            }
        }

        char decision;
        if (allow_all) {
            decision = 'y';
        } else {
            std::printf("%s%s[%s]%s pid=%d FROZEN in %s%s%s\n",
                        BOLD, RED, ts_now().c_str(), NC, req->pid,
                        BOLD, syscall_name(nr), NC);
            std::printf("        args: [0]=0x%llx [1]=0x%llx [2]=0x%llx\n",
                        (unsigned long long)req->data.args[0],
                        (unsigned long long)req->data.args[1],
                        (unsigned long long)req->data.args[2]);
            std::printf("        decision (%sy%s/%sn%s/%sk%s/%sA%s): ",
                        GRN, NC, YLW, NC, RED, NC, MAG, NC);
            std::fflush(stdout);
            decision = read_key_blocking();
            std::printf("%c\n", decision ? decision : '?');
            std::fflush(stdout);
        }

        std::memset(resp, 0, sizes.seccomp_notif_resp);
        resp->id = req->id;

        if (decision == 'A') { allow_all = true; decision = 'y'; }

        if (decision == 'k' || decision == 'K') {
            resp->error = -EPERM;
            resp->flags = 0;
            ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, resp);
            kill(child, SIGKILL);
            std::printf("        %s-> KILLED process group%s\n", RED, NC);
            denied++;
            break;
        } else if (decision == 'n' || decision == 'N') {
            resp->error = -EPERM;
            resp->flags = 0;
            denied++;
            std::printf("        %s-> DENIED (syscall returns EPERM)%s\n", YLW, NC);
        } else {
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            allowed++;
            if (cfg.log_allowed && !allow_all)
                std::printf("        %s-> ALLOWED (syscall proceeds)%s\n", GRN, NC);
        }
        if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, resp) != 0) {
            if (errno == ENOENT) continue;
        }
    }

    std::free(req);
    std::free(resp);
    std::printf("\n%s%s[edr-run]%s done. gated=%ld allowed=%ld denied=%ld\n",
                BOLD, CYN, NC, gated, allowed, denied);
    return 0;
}

int harness_run(const std::vector<std::string> &argv, const HarnessCfg &cfg) {
    if (argv.empty()) { std::fprintf(stderr, "no target\n"); return 2; }

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        std::perror("socketpair"); return 1;
    }

    pid_t child = fork();
    if (child < 0) { std::perror("fork"); return 1; }

    if (child == 0) {
        close(sv[0]);
        int nfd = install_filter_and_get_fd(cfg);
        if (nfd < 0) { _exit(127); }
        if (send_fd_over(sv[1], nfd) != 0) { std::perror("send_fd"); _exit(127); }
        close(nfd);
        close(sv[1]);
        std::vector<char *> cargv;
        for (auto &s : argv) cargv.push_back(const_cast<char *>(s.c_str()));
        cargv.push_back(nullptr);
        execvp(cargv[0], cargv.data());
        std::perror("execvp");
        _exit(127);
    }

    close(sv[1]);
    int notify_fd = recv_fd_over(sv[0]);
    close(sv[0]);
    if (notify_fd < 0) {
        std::fprintf(stderr, "failed to receive seccomp notify fd\n");
        kill(child, SIGKILL);
        return 1;
    }

    int rc = supervisor_loop(notify_fd, child, cfg);
    int st = 0;
    waitpid(child, &st, 0);
    close(notify_fd);
    return rc;
}