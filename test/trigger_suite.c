#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static int t_memfd(void) {
    int fd = syscall(SYS_memfd_create, "edrtest", 0);
    if (fd < 0) { perror("memfd_create"); return 1; }
    int src = open("/bin/true", O_RDONLY);
    if (src < 0) { fprintf(stderr, "no /bin/true; benign fallback\n"); close(fd); return 0; }
    char buf[65536]; ssize_t n;
    while ((n = read(src, buf, sizeof(buf))) > 0) {
        if (write(fd, buf, n) != n) { close(src); close(fd); return 1; }
    }
    close(src);
    pid_t p = fork();
    if (p == 0) {
        char *av[] = {(char*)"true", NULL};
        fexecve(fd, av, environ);
        _exit(127);
    } else if (p > 0) {
        int st; waitpid(p, &st, 0);
        printf("memfd trigger: exec status=%d\n", WEXITSTATUS(st));
    }
    close(fd);
    return 0;
}

static int t_prctl(void) {
    pid_t p = fork();
    if (p == 0) {
        if (prctl(PR_SET_NAME, "kworker/impostor", 0, 0, 0) != 0) perror("prctl");
        else printf("prctl trigger: renamed self\n");
        _exit(0);
    } else if (p > 0) {
        int st; waitpid(p, &st, 0);
    }
    return 0;
}

static int t_mprot(void) {
    long ps = sysconf(_SC_PAGESIZE);
    void *m = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) { perror("mmap"); return 1; }
    if (mprotect(m, ps, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        perror("mprotect");
        munmap(m, ps);
        return 1;
    }
    printf("mprotect trigger: RWX page at %p\n", m);
    munmap(m, ps);
    return 0;
}

static int t_forkchain(void) {
    pid_t a = fork();
    if (a == 0) {
        pid_t b = fork();
        if (b == 0) {
            pid_t c = fork();
            if (c == 0) {
                usleep(200 * 1000);
                _exit(0);
            } else if (c > 0) {
                int st; waitpid(c, &st, 0);
                _exit(0);
            }
            _exit(1);
        } else if (b > 0) {
            int st; waitpid(b, &st, 0);
            _exit(0);
        }
        _exit(1);
    } else if (a > 0) {
        int st; waitpid(a, &st, 0);
        printf("forkchain trigger: parent -> child -> grandchild -> gg completed\n");
    }
    return 0;
}

static int t_unshare(void) {
    pid_t p = fork();
    if (p == 0) {
        int r = syscall(SYS_unshare, 0x20000000);
        if (r != 0) fprintf(stderr, "unshare(CLONE_NEWUSER): %s\n", strerror(errno));
        else printf("unshare trigger: new user namespace\n");
        _exit(0);
    } else if (p > 0) {
        int st; waitpid(p, &st, 0);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s {memfd|prctl|mprot|forkchain|unshare|all}\n", argv[0]);
        return 2;
    }
    const char *cmd = argv[1];
    if (!strcmp(cmd, "memfd")) return t_memfd();
    if (!strcmp(cmd, "prctl")) return t_prctl();
    if (!strcmp(cmd, "mprot")) return t_mprot();
    if (!strcmp(cmd, "forkchain")) return t_forkchain();
    if (!strcmp(cmd, "unshare")) return t_unshare();
    if (!strcmp(cmd, "all")) {
        t_memfd(); sleep(1);
        t_prctl(); sleep(1);
        t_mprot(); sleep(1);
        t_forkchain(); sleep(1);
        t_unshare();
        return 0;
    }
    fprintf(stderr, "unknown trigger: %s\n", cmd);
    return 2;
}