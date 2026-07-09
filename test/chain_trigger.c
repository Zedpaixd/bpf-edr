#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif

#define S_MEMFD   0x01
#define S_WX      0x02
#define S_RENAME  0x04
#define S_UNSHARE 0x08
#define S_CONNECT 0x10

static int STEP_DELAY = 0;

static void st_memfd(void) {
    int fd = syscall(SYS_memfd_create, "ct_exec", 0);
    if (fd < 0) fprintf(stderr, "  memfd_create: %s\n", strerror(errno));
    else { printf("  [X] memfd_create fd=%d\n", fd); fflush(stdout); close(fd); }
}
static void st_wx(void) {
    long ps = sysconf(_SC_PAGESIZE);
    void *m = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) { fprintf(stderr, "  mmap: %s\n", strerror(errno)); return; }
    if (mprotect(m, ps, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        fprintf(stderr, "  mprotect WX: %s\n", strerror(errno));
    else { printf("  [M] mprotect RWX at %p\n", m); fflush(stdout); }
    mprotect(m, ps, PROT_READ | PROT_WRITE);
    munmap(m, ps);
}
static void st_rename(void) {
    if (prctl(PR_SET_NAME, "kworker/0:9H", 0, 0, 0) != 0)
        fprintf(stderr, "  prctl: %s\n", strerror(errno));
    else { printf("  [E] renamed self -> kworker/0:9H\n"); fflush(stdout); }
}
static void st_unshare(void) {
    long r = syscall(SYS_unshare, CLONE_NEWUSER);
    if (r != 0) fprintf(stderr, "  [P] unshare entered (rc: %s)\n", strerror(errno));
    else { printf("  [P] unshare(CLONE_NEWUSER) ok\n"); fflush(stdout); }
}
static void st_connect(void) {
    int s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (s < 0) { fprintf(stderr, "  socket: %s\n", strerror(errno)); return; }
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET; a.sin_port = htons(80);
    inet_pton(AF_INET, "192.0.2.1", &a.sin_addr);
    connect(s, (struct sockaddr *)&a, sizeof(a));
    printf("  [C] tcp connect -> 192.0.2.1:80 (unroutable)\n"); fflush(stdout);
    close(s);
}

static void do_stage(unsigned mask, unsigned bit, void (*fn)(void)) {
    if (!(mask & bit)) return;
    fn();
    sleep(STEP_DELAY);
}

static int worker(unsigned mask) {
    setpgid(0, 0);
    printf("  [worker pid=%d] stepping through stages (%ds apart)\n", getpid(), STEP_DELAY);
    fflush(stdout);
    do_stage(mask, S_MEMFD, st_memfd);
    do_stage(mask, S_WX, st_wx);
    do_stage(mask, S_RENAME, st_rename);
    do_stage(mask, S_UNSHARE, st_unshare);
    do_stage(mask, S_CONNECT, st_connect);
    printf("  [worker pid=%d] all stages done, exiting\n", getpid());
    fflush(stdout);
    _exit(0);
}

static int run_benign(void) {
    setpgid(0, 0);
    for (int i = 0; i < 2; i++) {
        pid_t p = fork();
        if (p == 0) { char *av[] = {(char *)"true", NULL}; execv("/bin/true", av); _exit(127); }
        else if (p > 0) { int st; waitpid(p, &st, 0); }
    }
    printf("  benign: forked 2 children, exec /bin/true\n");
    return 0;
}

static int spawn_worker(unsigned mask) {
    setpgid(0, 0);
    pid_t p = fork();
    if (p == 0) worker(mask);
    if (p > 0) { int st; waitpid(p, &st, 0); }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s {benign|single|two|three|four|full} [step_delay_sec]\n", argv[0]);
        return 2;
    }
    if (argc >= 3) { int d = atoi(argv[2]); if (d > 0 && d < 60) STEP_DELAY = d; }
    const char *s = argv[1];
    if (!strcmp(s, "benign")) return run_benign();
    if (!strcmp(s, "single")) return spawn_worker(S_WX);
    if (!strcmp(s, "two"))    return spawn_worker(S_MEMFD | S_WX);
    if (!strcmp(s, "three"))  return spawn_worker(S_MEMFD | S_WX | S_RENAME);
    if (!strcmp(s, "four"))   return spawn_worker(S_MEMFD | S_WX | S_RENAME | S_UNSHARE);
    if (!strcmp(s, "full"))
        return spawn_worker(S_MEMFD | S_WX | S_RENAME | S_UNSHARE | S_CONNECT);
    fprintf(stderr, "unknown scenario: %s\n", s);
    return 2;
}