#include "seccomp_supervisor.h"
#include "tracker.h"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

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

static constexpr std::size_t OUT_CAP = 500;

static long seccomp_raw(unsigned int op, unsigned int flags, void *args) {
    return syscall(__NR_seccomp, op, flags, args);
}

SeccompSupervisor::SeccompSupervisor() {}

SeccompSupervisor::~SeccompSupervisor() {
    stop();
    if (thread_.joinable()) thread_.join();
    if (reader_thread_.joinable()) reader_thread_.join();
    if (notify_fd_ >= 0) ::close(notify_fd_);
    if (pty_master_ >= 0) ::close(pty_master_);
}

std::string SeccompSupervisor::last_error() const {
    std::lock_guard<std::mutex> lk(err_mtx_);
    return err_;
}

bool SeccompSupervisor::launch(const std::vector<std::string> &argv,
                               const SeccompGates &gates, std::string &err) {
    if (active_.load()) { err = "a supervised process is already running"; return false; }
    if (argv.empty()) { err = "no target specified"; return false; }

    if (thread_.joinable()) thread_.join();
    if (reader_thread_.joinable()) reader_thread_.join();
    if (notify_fd_ >= 0) { ::close(notify_fd_); notify_fd_ = -1; }
    if (pty_master_ >= 0) { ::close(pty_master_); pty_master_ = -1; }

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        err = std::string("socketpair: ") + std::strerror(errno);
        return false;
    }

    int master = -1;
    pid_t child = forkpty(&master, nullptr, nullptr, nullptr);
    if (child < 0) {
        err = std::string("forkpty: ") + std::strerror(errno);
        ::close(sv[0]); ::close(sv[1]);
        return false;
    }

    if (child == 0) {
        ::close(sv[0]);
        int nfd = seccomp_install_filter(gates);
        if (nfd < 0) _exit(127);
        if (seccomp_send_fd(sv[1], nfd) != 0) _exit(127);
        ::close(nfd);
        ::close(sv[1]);
        std::vector<char *> cargv;
        for (auto &s : argv) cargv.push_back(const_cast<char *>(s.c_str()));
        cargv.push_back(nullptr);
        execvp(cargv[0], cargv.data());
        _exit(127);
    }

    ::close(sv[1]);
    int nfd = seccomp_recv_fd(sv[0]);
    ::close(sv[0]);
    if (nfd < 0) {
        err = "failed to receive seccomp notify fd (target exec failed?)";
        kill(child, SIGKILL);
        int st; waitpid(child, &st, 0);
        ::close(master);
        return false;
    }

    int fl = fcntl(master, F_GETFL, 0);
    fcntl(master, F_SETFL, fl | O_NONBLOCK);

    notify_fd_ = nfd;
    pty_master_ = master;
    child_pid_.store((std::uint32_t)child);
    if (tr_) tr_->register_supervised((std::uint32_t)child);
    gated_.store(0);
    stop_.store(false);
    {
        std::lock_guard<std::mutex> lk(out_mtx_);
        out_lines_.clear();
        out_partial_.clear();
        out_lines_.push_back("[supervised process started: pid " + std::to_string(child) + "]");
    }
    active_.store(true);
    thread_ = std::thread(&SeccompSupervisor::supervise, this);
    if (pty_master_ >= 0)
        reader_thread_ = std::thread(&SeccompSupervisor::reader, this);
    return true;
}

void SeccompSupervisor::reader() {
    char buf[4096];
    int esc_state = 0;
    while (!stop_.load()) {
        struct pollfd pfd;
        pfd.fd = pty_master_;
        pfd.events = POLLIN;
        int pr = poll(&pfd, 1, 200);
        if (pr <= 0) {
            if (pr < 0 && errno != EINTR) break;
            if (!active_.load()) break;
            continue;
        }
        ssize_t n = read(pty_master_, buf, sizeof(buf));
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
            break;
        }
        std::lock_guard<std::mutex> lk(out_mtx_);
        for (ssize_t i = 0; i < n; i++) {
            unsigned char c = (unsigned char)buf[i];

            if (esc_state == 1) {
                if (c == '[' || c == ']' || c == '(' || c == ')') { esc_state = 2; continue; }
                esc_state = 0;
                continue;
            }
            if (esc_state == 2) {
                if ((c >= '@' && c <= '~')) esc_state = 0;
                continue;
            }
            if (c == 0x1b) { esc_state = 1; continue; }
            if (c == '\n') {
                out_lines_.push_back(out_partial_);
                out_partial_.clear();
                if (out_lines_.size() > OUT_CAP) out_lines_.pop_front();
            } else if (c == '\r' || c == 0x07 || c == 0x08) {
                continue;
            } else if (c >= 0x20 || c == '\t') {
                out_partial_ += (char)c;
                if (out_partial_.size() > 2048) {
                    out_lines_.push_back(out_partial_);
                    out_partial_.clear();
                    if (out_lines_.size() > OUT_CAP) out_lines_.pop_front();
                }
            }
        }
    }
}

std::vector<std::string> SeccompSupervisor::output_lines(std::size_t max_lines) {
    std::lock_guard<std::mutex> lk(out_mtx_);
    std::vector<std::string> out;
    std::size_t total = out_lines_.size() + (out_partial_.empty() ? 0 : 1);
    std::size_t start = (total > max_lines) ? (total - max_lines) : 0;
    std::size_t idx = 0;
    for (auto &l : out_lines_) {
        if (idx++ >= start) out.push_back(l);
    }
    if (!out_partial_.empty() && (idx++ >= start)) out.push_back(out_partial_ + " \u2588");
    return out;
}

void SeccompSupervisor::write_stdin(const std::string &line) {
    if (pty_master_ < 0) return;
    std::string data = line + "\n";
    ssize_t off = 0;
    while (off < (ssize_t)data.size()) {
        ssize_t w = write(pty_master_, data.data() + off, data.size() - off);
        if (w <= 0) {
            if (errno == EAGAIN || errno == EINTR) continue;
            break;
        }
        off += w;
    }
    std::lock_guard<std::mutex> lk(out_mtx_);
    out_lines_.push_back("> " + line);
    if (out_lines_.size() > OUT_CAP) out_lines_.pop_front();
}

void SeccompSupervisor::supervise() {
    struct seccomp_notif_sizes sizes;
    if (seccomp_raw(SECCOMP_GET_NOTIF_SIZES, 0, &sizes) < 0) {
        std::lock_guard<std::mutex> lk(err_mtx_);
        err_ = "GET_NOTIF_SIZES failed";
        active_.store(false);
        return;
    }
    struct seccomp_notif *req = (struct seccomp_notif *)std::calloc(1, sizes.seccomp_notif);
    struct seccomp_notif_resp *resp =
        (struct seccomp_notif_resp *)std::calloc(1, sizes.seccomp_notif_resp);
    if (!req || !resp) {
        std::free(req); std::free(resp);
        active_.store(false);
        return;
    }

    while (!stop_.load()) {
        std::memset(req, 0, sizes.seccomp_notif);

        struct pollfd pfd;
        pfd.fd = notify_fd_;
        pfd.events = POLLIN;
        int pr = poll(&pfd, 1, 200);
        if (pr <= 0) {
            if (pr < 0 && errno != EINTR) break;
            std::uint32_t cp = child_pid_.load();
            if (cp > 1) {
                int st;
                if (waitpid((pid_t)cp, &st, WNOHANG) == (pid_t)cp) break;
            }
            continue;
        }

        if (ioctl(notify_fd_, SECCOMP_IOCTL_NOTIF_RECV, req) != 0) {
            if (errno == EINTR) continue;
            break;
        }
        int nr = req->data.nr;
        gated_.fetch_add(1);

        SeccompPrompt p;
        p.token = token_seq_.fetch_add(1);
        p.pid = req->pid;
        p.syscall_nr = nr;
        p.syscall_label = seccomp_syscall_label(nr);
        p.args[0] = req->data.args[0];
        p.args[1] = req->data.args[1];
        p.args[2] = req->data.args[2];

        if (tr_) {
            RiskPrediction rp = tr_->predict_for_syscall(p.pid, nr,
                                                         p.args[0], p.args[1], p.args[2]);
            p.risk_known = rp.known;
            p.risk_current = rp.current;
            p.risk_predicted = rp.predicted;
            p.scores_ebpf = rp.scores;
            p.comm = rp.comm;
            p.exe_path = rp.exe_path;
        }

        {
            std::lock_guard<std::mutex> lk(q_mtx_);
            prompts_.push_back(p);
        }

        SeccompDecision d = SD_PENDING;
        {
            std::unique_lock<std::mutex> lk(dec_mtx_);
            awaiting_token_ = p.token;
            decision_ = SD_PENDING;
            dec_cv_.wait(lk, [&] { return decision_ != SD_PENDING || stop_.load(); });
            d = stop_.load() ? SD_ALLOW : decision_;
            awaiting_token_ = 0;
        }

        std::memset(resp, 0, sizes.seccomp_notif_resp);
        resp->id = req->id;

        bool do_kill = false;
        switch (d) {
            case SD_DENY:
            case SD_BLACKLIST:
                resp->error = -EPERM;
                resp->flags = 0;
                break;
            case SD_KILL:
                resp->error = -EPERM;
                resp->flags = 0;
                do_kill = true;
                break;
            case SD_ALLOW:
            case SD_WHITELIST:
            default:
                resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                break;
        }

        if (tr_) {
            if (d == SD_BLACKLIST) tr_->seccomp_persist_hash(p.pid, true);
            else if (d == SD_WHITELIST) tr_->seccomp_persist_hash(p.pid, false);
        }

        ioctl(notify_fd_, SECCOMP_IOCTL_NOTIF_SEND, resp);

        if (do_kill) {
            std::uint32_t cp = child_pid_.load();
            if (cp > 1) kill((pid_t)cp, SIGKILL);
            break;
        }
    }

    std::free(req);
    std::free(resp);

    std::uint32_t cp = child_pid_.load();
    if (cp > 1) { int st; waitpid((pid_t)cp, &st, WNOHANG); }
    {
        std::lock_guard<std::mutex> lk(out_mtx_);
        out_lines_.push_back("[supervised process ended]");
        if (out_lines_.size() > OUT_CAP) out_lines_.pop_front();
    }
    active_.store(false);
    dec_cv_.notify_all();
}

bool SeccompSupervisor::has_prompt() {
    std::lock_guard<std::mutex> lk(q_mtx_);
    return !prompts_.empty();
}

bool SeccompSupervisor::peek_prompt(SeccompPrompt &out) {
    std::lock_guard<std::mutex> lk(q_mtx_);
    if (prompts_.empty()) return false;
    out = prompts_.front();
    return true;
}

void SeccompSupervisor::resolve(std::uint64_t token, SeccompDecision d) {
    {
        std::lock_guard<std::mutex> lk(q_mtx_);
        if (!prompts_.empty() && prompts_.front().token == token)
            prompts_.pop_front();
    }
    {
        std::lock_guard<std::mutex> lk(dec_mtx_);
        if (awaiting_token_ == token) {
            decision_ = d;
            dec_cv_.notify_all();
        }
    }
}

void SeccompSupervisor::stop() {
    stop_.store(true);
    {
        std::lock_guard<std::mutex> lk(dec_mtx_);
        decision_ = SD_ALLOW;
    }
    dec_cv_.notify_all();
}