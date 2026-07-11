#include "seccomp_filter.h"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <string>
#include <vector>

#ifndef SECCOMP_GET_NOTIF_SIZES
#define SECCOMP_GET_NOTIF_SIZES 3
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

static long seccomp_raw(unsigned int op, unsigned int flags, void *args) {
    return syscall(__NR_seccomp, op, flags, args);
}

static char read_tty() {
    int tty = ::open("/dev/tty", O_RDONLY);
    if (tty < 0) tty = STDIN_FILENO;
    struct termios old, raw;
    tcgetattr(tty, &old);
    raw = old; raw.c_lflag &= ~(ICANON | ECHO);
    raw.c_cc[VMIN] = 1; raw.c_cc[VTIME] = 0;
    tcsetattr(tty, TCSANOW, &raw);
    char c = 0; ssize_t n = read(tty, &c, 1);
    tcsetattr(tty, TCSANOW, &old);
    if (tty != STDIN_FILENO) ::close(tty);
    return n <= 0 ? 0 : c;
}

int main(int argc, char **argv) {
    std::vector<std::string> target;
    int i = 1;
    for (; i < argc; i++) { std::string a = argv[i]; if (a == "--") { i++; break; } }
    for (; i < argc; i++) target.push_back(argv[i]);
    if (target.empty()) {
        std::printf("usage: %s -- <binary> [args...]   (debug seccomp harness)\n", argv[0]);
        return 2;
    }

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); return 1; }
    pid_t child = fork();
    if (child < 0) { perror("fork"); return 1; }
    if (child == 0) {
        ::close(sv[0]);
        SeccompGates g;
        int nfd = seccomp_install_filter(g);
        if (nfd < 0) _exit(127);
        if (seccomp_send_fd(sv[1], nfd) != 0) _exit(127);
        ::close(nfd); ::close(sv[1]);
        std::vector<char *> ca;
        for (auto &s : target) ca.push_back(const_cast<char *>(s.c_str()));
        ca.push_back(nullptr);
        execvp(ca[0], ca.data());
        perror("execvp"); _exit(127);
    }
    ::close(sv[1]);
    int nfd = seccomp_recv_fd(sv[0]);
    ::close(sv[0]);
    if (nfd < 0) { std::fprintf(stderr, "no notify fd\n"); kill(child, SIGKILL); return 1; }

    struct seccomp_notif_sizes sizes;
    seccomp_raw(SECCOMP_GET_NOTIF_SIZES, 0, &sizes);
    struct seccomp_notif *req = (struct seccomp_notif *)std::calloc(1, sizes.seccomp_notif);
    struct seccomp_notif_resp *resp =
        (struct seccomp_notif_resp *)std::calloc(1, sizes.seccomp_notif_resp);

    std::printf("[edr-run debug] supervising pid=%d. keys: y allow / n deny / k kill / A allow-all\n", child);
    bool allow_all = false;
    for (;;) {
        std::memset(req, 0, sizes.seccomp_notif);
        if (ioctl(nfd, SECCOMP_IOCTL_NOTIF_RECV, req) != 0) {
            if (errno == EINTR) continue;
            break;
        }
        char d = 'y';
        if (!allow_all) {
            std::printf("FROZEN pid=%d in %s  [y/n/k/A]: ",
                        req->pid, seccomp_syscall_label(req->data.nr));
            std::fflush(stdout);
            d = read_tty();
            std::printf("%c\n", d ? d : '?');
        }
        std::memset(resp, 0, sizes.seccomp_notif_resp);
        resp->id = req->id;
        if (d == 'A') { allow_all = true; d = 'y'; }
        if (d == 'k') { resp->error = -EPERM; ioctl(nfd, SECCOMP_IOCTL_NOTIF_SEND, resp); kill(child, SIGKILL); break; }
        else if (d == 'n') { resp->error = -EPERM; }
        else { resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE; }
        ioctl(nfd, SECCOMP_IOCTL_NOTIF_SEND, resp);
    }
    std::free(req); std::free(resp);
    int st; waitpid(child, &st, 0);
    std::printf("[edr-run debug] done.\n");
    return 0;
}