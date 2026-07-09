#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif

static int   G_FD = -1;
static long  G_N = 0;
static int   ROUNDS = 3;

static void tick(const char *tag) {
    G_N++;
    char b[64];
    int len = snprintf(b, sizeof(b), "%ld %s\n", G_N, tag);
    if (G_FD >= 0 && len > 0) { ssize_t w = write(G_FD, b, (size_t)len); (void)w; }
}

static void s_memfd(void) {
    tick("memfd_create");
    int fd = syscall(SYS_memfd_create, "flood", 0);
    if (fd >= 0) close(fd);
}

static void s_wx(void) {
    tick("mprotect_WX");
    long ps = sysconf(_SC_PAGESIZE);
    void *m = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) return;
    mprotect(m, ps, PROT_READ | PROT_WRITE | PROT_EXEC);
    mprotect(m, ps, PROT_READ | PROT_WRITE);
    munmap(m, ps);
}

static void s_ptrace(void) {
    tick("ptrace");
    pid_t child = fork();
    if (child == 0) { _exit(0); }
    if (child > 0) {
        syscall(SYS_ptrace, PTRACE_ATTACH, child, 0, 0);
        syscall(SYS_ptrace, PTRACE_DETACH, child, 0, 0);
        int st; waitpid(child, &st, 0);
    }
}

static void s_unshare(void) {
    tick("unshare");
    pid_t p = fork();
    if (p == 0) { syscall(SYS_unshare, CLONE_NEWUSER); _exit(0); }
    if (p > 0) { int st; waitpid(p, &st, 0); }
}

static void s_rename(void) {
    tick("prctl_rename");
    prctl(PR_SET_NAME, "kworker/0:9H", 0, 0, 0);
    prctl(PR_SET_NAME, "flood_trigger", 0, 0, 0);
}

static void s_connect(void) {
    tick("tcp_connect");
    int s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (s < 0) return;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(80);
    inet_pton(AF_INET, "192.0.2.1", &a.sin_addr);
    connect(s, (struct sockaddr *)&a, sizeof(a));
    close(s);
}

static void s_exec_probe(void) {
    tick("execve_probe");
    pid_t p = fork();
    if (p == 0) { char *av[] = {(char *)"true", NULL}; execv("/bin/true", av); _exit(127); }
    if (p > 0) { int st; waitpid(p, &st, 0); }
}

static void round_burst(int r) {
    char tag[32];
    snprintf(tag, sizeof(tag), "R%d", r);
    tick(tag);

    for (int i = 0; i < 8; i++)  s_memfd();
    for (int i = 0; i < 12; i++) s_wx();
    for (int i = 0; i < 4; i++)  s_ptrace();
    for (int i = 0; i < 3; i++)  s_unshare();
    for (int i = 0; i < 6; i++)  s_rename();
    for (int i = 0; i < 5; i++)  s_connect();
    for (int i = 0; i < 3; i++)  s_exec_probe();
}

static int worker(void) {
    setpgid(0, 0);
    tick("START");
    for (int r = 1; r <= ROUNDS; r++) round_burst(r);
    tick("DONE");
    _exit(0);
}

int main(int argc, char **argv) {
    const char *path = "/tmp/flood_progress.txt";
    if (argc >= 2) path = argv[1];
    if (argc >= 3) { int n = atoi(argv[2]); if (n > 0 && n <= 20) ROUNDS = n; }

    G_FD = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (G_FD < 0) { perror("open progress file"); return 1; }

    printf("flood_trigger: progress -> %s | rounds=%d\n", path, ROUNDS);
    printf("  watch live:  tail -f %s\n", path);
    printf("  each line = one syscall about to fire; freeze halts the count.\n");
    fflush(stdout);

    pid_t p = fork();
    if (p == 0) worker();
    if (p > 0) {
        int st;
        waitpid(p, &st, 0);
        printf("flood_trigger: worker finished/terminated.\n");
    }
    close(G_FD);
    return 0;
}