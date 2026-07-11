#ifndef EDR_SECCOMP_SUPERVISOR_H
#define EDR_SECCOMP_SUPERVISOR_H

#include "seccomp_filter.h"
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

enum SeccompDecision {
    SD_PENDING = 0,
    SD_ALLOW,
    SD_DENY,
    SD_KILL,
    SD_BLACKLIST,
    SD_WHITELIST
};

struct SeccompPrompt {
    std::uint64_t token = 0;
    std::uint32_t pid = 0;
    int syscall_nr = 0;
    std::string syscall_label;
    std::string comm;
    std::string exe_path;
    std::uint64_t args[3] = {0, 0, 0};
    double risk_current = -1.0;
    double risk_predicted = -1.0;
    bool risk_known = false;
    bool scores_ebpf = false;
};

class Tracker;

class SeccompSupervisor {
public:
    SeccompSupervisor();
    ~SeccompSupervisor();

    bool launch(const std::vector<std::string> &argv, const SeccompGates &gates,
                std::string &err);
    void attach_tracker(Tracker *tr) { tr_ = tr; }

    bool has_prompt();
    bool peek_prompt(SeccompPrompt &out);
    void resolve(std::uint64_t token, SeccompDecision d);

    std::vector<std::string> output_lines(std::size_t max_lines);
    void write_stdin(const std::string &line);

    void set_skip_unscored(bool on) { skip_unscored_.store(on); }
    bool skip_unscored() const { return skip_unscored_.load(); }
    std::uint64_t auto_allowed() const { return auto_allowed_.load(); }

    void stop();
    bool active() const { return active_.load(); }
    std::uint32_t child_pid() const { return child_pid_.load(); }
    std::uint64_t gated_count() const { return gated_.load(); }
    std::string last_error() const;

private:
    void supervise();
    void reader();

    Tracker *tr_ = nullptr;
    std::thread thread_;
    std::thread reader_thread_;
    std::atomic<bool> active_{false};
    std::atomic<bool> stop_{false};
    std::atomic<bool> skip_unscored_{true};
    std::atomic<std::uint32_t> child_pid_{0};
    std::atomic<std::uint64_t> gated_{0};
    std::atomic<std::uint64_t> auto_allowed_{0};
    std::atomic<std::uint64_t> token_seq_{1};
    int notify_fd_ = -1;
    int pty_master_ = -1;

    std::mutex out_mtx_;
    std::deque<std::string> out_lines_;
    std::string out_partial_;

    std::mutex q_mtx_;
    std::deque<SeccompPrompt> prompts_;

    std::mutex dec_mtx_;
    std::condition_variable dec_cv_;
    std::uint64_t awaiting_token_ = 0;
    SeccompDecision decision_ = SD_PENDING;

    mutable std::mutex err_mtx_;
    std::string err_;
};

#endif