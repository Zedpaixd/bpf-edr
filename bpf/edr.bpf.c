#define EDR_BPF_SIDE
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

#define PR_SET_NAME 15
#define AF_INET 2

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct exec_ctx);
} exec_state SEC(".maps");

struct str_scratch { char buf[MAX_ARG_LEN]; };

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct str_scratch);
} str_buf SEC(".maps");

static __always_inline __u32 rd_pgid(struct task_struct *t) {
    if (!t) return 0;
    struct signal_struct *s = BPF_CORE_READ(t, signal);
    if (!s) return 0;
    struct pid *pp = BPF_CORE_READ(s, pids[PIDTYPE_PGID]);
    if (!pp) return 0;
    return BPF_CORE_READ(pp, numbers[0].nr);
}

static __always_inline __u32 rd_nsinum(struct task_struct *t) {
    if (!t) return 0;
    struct nsproxy *n = BPF_CORE_READ(t, nsproxy);
    if (!n) return 0;
    return BPF_CORE_READ(n, mnt_ns, ns.inum);
}

static __always_inline __u32 rd_ppid(struct task_struct *t) {
    if (!t) return 0;
    return BPF_CORE_READ(t, real_parent, tgid);
}

static __always_inline void fill_meta(struct edr_event *e) {
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    __u64 pt = bpf_get_current_pid_tgid();
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = (__u32)pt;
    e->tgid = (__u32)(pt >> 32);
    e->ppid = rd_ppid(t);
    e->pgid = rd_pgid(t);
    e->uid = (__u32)bpf_get_current_uid_gid();
    e->ns_inum = rd_nsinum(t);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline struct edr_event *ev_reserve(__u8 ty) {
    struct edr_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    e->ev_type = ty;
    return e;
}

SEC("tracepoint/sched/sched_process_fork")
int tp_fork(struct trace_event_raw_sched_process_fork *ctx) {
    struct edr_event *e = ev_reserve(EV_FORK);
    if (!e) return 0;
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = ctx->child_pid;
    e->tgid = ctx->child_pid;
    e->ppid = ctx->parent_pid;
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    e->pgid = rd_pgid(t);
    e->uid = (__u32)bpf_get_current_uid_gid();
    e->ns_inum = rd_nsinum(t);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int tp_exit(struct trace_event_raw_sched_process_template *ctx) {
    __u64 pt = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)pt;
    __u32 tgid = (__u32)(pt >> 32);
    if (pid != tgid) return 0;
    struct edr_event *e = ev_reserve(EV_EXIT);
    if (!e) return 0;
    fill_meta(e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline void grab_argv(const char *const *argv, char *dst) {
    const char *p = 0;
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        if (bpf_probe_read_user(&p, sizeof(p), &argv[i]) != 0) return;
        if (!p) return;
        long n = bpf_probe_read_user_str(&dst[i * 64], 63, p);
        if (n <= 0) return;
    }
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tp_execve(struct trace_event_raw_sys_enter *ctx) {
    __u32 k = 0;
    struct str_scratch *s = bpf_map_lookup_elem(&str_buf, &k);
    if (!s) return 0;
    __builtin_memset(s->buf, 0, MAX_ARG_LEN);
    grab_argv((const char *const *)ctx->args[1], s->buf);
    struct edr_event *e = ev_reserve(EV_EXEC);
    if (!e) return 0;
    fill_meta(e);
    __builtin_memcpy(e->data.exec.argbuf, s->buf, MAX_ARG_LEN);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int tp_execveat(struct trace_event_raw_sys_enter *ctx) {
    __u32 k = 0;
    struct str_scratch *s = bpf_map_lookup_elem(&str_buf, &k);
    if (!s) return 0;
    __builtin_memset(s->buf, 0, MAX_ARG_LEN);
    grab_argv((const char *const *)ctx->args[2], s->buf);
    struct edr_event *e = ev_reserve(EV_EXEC);
    if (!e) return 0;
    fill_meta(e);
    __builtin_memcpy(e->data.exec.argbuf, s->buf, MAX_ARG_LEN);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_prctl")
int tp_prctl(struct trace_event_raw_sys_enter *ctx) {
    __u32 op = (__u32)ctx->args[0];
    if (op != PR_SET_NAME) return 0;
    const char *nm = (const char *)ctx->args[1];
    struct edr_event *e = ev_reserve(EV_PRCTL_RENAME);
    if (!e) return 0;
    fill_meta(e);
    bpf_probe_read_user_str(e->data.rename.new_name, MAX_COMM, nm);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int tp_ptrace(struct trace_event_raw_sys_enter *ctx) {
    struct edr_event *e = ev_reserve(EV_PTRACE);
    if (!e) return 0;
    fill_meta(e);
    e->data.ptrace_ev.req = (__u32)ctx->args[0];
    e->data.ptrace_ev.tgt_pid = (__u32)ctx->args[1];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int tp_unshare(struct trace_event_raw_sys_enter *ctx) {
    struct edr_event *e = ev_reserve(EV_UNSHARE);
    if (!e) return 0;
    fill_meta(e);
    e->data.unshare_ev.flags = (__u32)ctx->args[0];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int tp_mprotect(struct trace_event_raw_sys_enter *ctx) {
    __u32 prot = (__u32)ctx->args[2];
    if (!((prot & 0x2) && (prot & 0x4))) return 0;
    struct edr_event *e = ev_reserve(EV_MPROTECT_WX);
    if (!e) return 0;
    fill_meta(e);
    e->data.mprot.addr = (__u64)ctx->args[0];
    e->data.mprot.len  = (__u64)ctx->args[1];
    e->data.mprot.prot = prot;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kretprobe/__x64_sys_memfd_create")
int krp_memfd(struct pt_regs *ctx) {
    long ret = PT_REGS_RC(ctx);
    if (ret < 0) return 0;
    struct edr_event *e = ev_reserve(EV_MEMFD_CREATE);
    if (!e) return 0;
    fill_meta(e);
    e->data.memfd.ret_fd = (__u32)ret;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/commit_creds")
int kp_commit_creds(struct pt_regs *ctx) {
    struct cred *newc = (struct cred *)PT_REGS_PARM1(ctx);
    if (!newc) return 0;
    __u32 nu = BPF_CORE_READ(newc, uid.val);
    __u32 cu = (__u32)bpf_get_current_uid_gid();
    if (nu != 0 || cu == 0) return 0;
    struct edr_event *e = ev_reserve(EV_COMMIT_CREDS);
    if (!e) return 0;
    fill_meta(e);
    e->data.creds.old_uid = cu;
    e->data.creds.new_uid = nu;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/security_bpf")
int kp_sec_bpf(struct pt_regs *ctx) {
    __u32 cmd = (__u32)PT_REGS_PARM1(ctx);
    struct edr_event *e = ev_reserve(EV_SEC_BPF);
    if (!e) return 0;
    fill_meta(e);
    e->data.unshare_ev.flags = cmd;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int kp_tcp_conn(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;
    __u16 fam = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (fam != AF_INET) return 0;
    struct edr_event *e = ev_reserve(EV_TCP_CONNECT);
    if (!e) return 0;
    fill_meta(e);
    e->data.net.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->data.net.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    __u16 dp = BPF_CORE_READ(sk, __sk_common.skc_dport);
    e->data.net.dport = (dp << 8) | (dp >> 8);
    bpf_ringbuf_submit(e, 0);
    return 0;
}