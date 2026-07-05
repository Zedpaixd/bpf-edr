#ifndef EDR_TRACKER_H
#define EDR_TRACKER_H

#include "common.h"
#include "math_engine.h"
#include <atomic>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

struct ProcNode {
    std::string uid;
    std::uint32_t pid = 0;
    std::uint32_t tgid = 0;
    std::uint32_t ppid = 0;
    std::uint32_t pgid = 0;
    std::uint32_t owner_uid = 0;
    std::uint32_t ns_inum = 0;
    char comm[MAX_COMM] = {0};
    double raw_score = 0.0;
    double decayed_score = 0.0;
    double risk_pct = 0.0;
    double last_ev_ts = 0.0;
    double created_ts = 0.0;
    double died_ts = 0.0;
    bool   is_dead = false;
    std::weak_ptr<ProcNode> parent;
    std::vector<std::shared_ptr<ProcNode>> children;
};

struct SnapNode {
    std::uint32_t pid = 0;
    std::string   comm;
    double        risk_pct = 0.0;
    double        raw_score = 0.0;
    bool          is_dead = false;
    std::vector<SnapNode> children;
};

struct TopEntry {
    std::uint32_t pid = 0;
    std::string   comm;
    double        risk_pct = 0.0;
};

struct Snapshot {
    std::vector<SnapNode> roots;
    std::vector<TopEntry> top3;
    std::size_t total_nodes = 0;
    std::size_t live_nodes = 0;
};

class Tracker {
public:
    Tracker(EngineCfg cfg, std::uint32_t own_pgid);
    void ingest(const edr_event &e);
    void tick();
    Snapshot snapshot() const;
    std::vector<std::string> tail_alerts(std::size_t n) const;
    void push_alert(const std::string &s);
    void stop();
    bool running() const { return running_.load(); }
    std::uint64_t kills_issued() const { return kills_.load(); }
    std::uint64_t hooks_failed() const { return hook_fails_.load(); }
    void note_hook_fail() { hook_fails_.fetch_add(1); }
    std::uint64_t ev_count() const { return ev_count_.load(); }

private:
    EngineCfg cfg_;
    std::uint32_t own_pgid_;
    mutable std::shared_mutex g_lock_;
    std::unordered_map<std::string, std::shared_ptr<ProcNode>> nodes_;
    std::unordered_map<std::uint32_t, std::string> pid_to_uid_;
    std::vector<std::shared_ptr<ProcNode>> roots_;
    mutable std::mutex alert_lock_;
    std::deque<std::string> alerts_;
    std::atomic<bool> running_{true};
    std::atomic<std::uint64_t> kills_{0};
    std::atomic<std::uint64_t> hook_fails_{0};
    std::atomic<std::uint64_t> ev_count_{0};

    std::string mk_uid(std::uint32_t tgid, std::uint64_t ts_ns) const;
    std::shared_ptr<ProcNode> lookup_by_pid(std::uint32_t tgid);
    std::shared_ptr<ProcNode> ensure_node(const edr_event &e);
    std::shared_ptr<ProcNode> fork_node(const edr_event &e);
    std::string ev_key(std::uint8_t t) const;
    double ctx_mult(const edr_event &e, const std::shared_ptr<ProcNode> &n) const;
    void apply_spike(std::shared_ptr<ProcNode> n, double spike, double ts_sec);
    void backprop(std::shared_ptr<ProcNode> n, double spike, int depth);
    SnapNode build_snap(const std::shared_ptr<ProcNode> &n) const;
    void collect_top(const std::shared_ptr<ProcNode> &n, std::vector<TopEntry> &out) const;
    void gc_sweep(double now_sec);
    void mitigate(std::shared_ptr<ProcNode> n);
    void detach_from_parent(const std::shared_ptr<ProcNode> &n);
};

#endif