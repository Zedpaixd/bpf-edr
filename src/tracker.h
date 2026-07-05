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
    double cat_accum[CAT_COUNT] = {0};
    double logodds = 0.0;
    double risk_pct = 0.0;
    double peak_risk_pct = 0.0;
    double last_score_ts = 0.0;
    double last_ev_ts = 0.0;
    double created_ts = 0.0;
    double died_ts = 0.0;
    double above_since = 0.0;
    bool   is_dead = false;
    bool   is_new = false;
    bool   exempt = false;
    bool   kill_flagged = false;
    std::weak_ptr<ProcNode> parent;
    std::vector<std::shared_ptr<ProcNode>> children;
};

struct SnapNode {
    std::uint32_t pid = 0;
    std::string   comm;
    double        risk_pct = 0.0;
    bool          is_dead = false;
    bool          is_new = false;
    bool          exempt = false;
    std::vector<SnapNode> children;
};

struct TopEntry {
    std::uint32_t pid = 0;
    std::string   comm;
    double        risk_pct = 0.0;
};

struct MasqEvent {
    std::string   tstr;
    std::uint32_t pid = 0;
    std::string   old_comm;
    std::string   new_comm;
    double        risk_pct = 0.0;
    bool          suspicious = false;
};

struct WatchEntry {
    std::string   uid;
    std::string   first_tstr;
    std::string   origin;
    std::uint32_t pid = 0;
    std::string   comm;
    std::string   stages;
    double        peak_risk_pct = 0.0;
    double        current_risk_pct = 0.0;
    std::size_t   child_count = 0;
    bool          is_dead = false;
};

struct Snapshot {
    std::vector<SnapNode>   roots;
    std::vector<TopEntry>   top3;
    std::vector<MasqEvent>  masq_events;
    std::vector<WatchEntry> watchlist;
    std::size_t total_nodes = 0;
    std::size_t live_nodes = 0;
    std::size_t new_nodes = 0;
};

class Tracker {
public:
    Tracker(EngineCfg cfg, std::uint32_t own_pgid, std::uint32_t own_pid);
    void seed_from_proc();
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
    std::uint32_t own_pid_;
    double start_ts_ = 0.0;
    mutable std::shared_mutex g_lock_;
    std::unordered_map<std::string, std::shared_ptr<ProcNode>> nodes_;
    std::unordered_map<std::uint32_t, std::string> pid_to_uid_;
    std::vector<std::shared_ptr<ProcNode>> roots_;
    std::deque<MasqEvent> masq_events_;
    std::unordered_map<std::string, WatchEntry> watchlist_;
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
    bool self_pid(std::uint32_t pid, std::uint32_t pgid) const;
    bool is_self(const edr_event &e) const;
    bool is_exempt_comm(const char *nm) const;
    bool is_masq_name(const char *nm) const;
    double ctx_mult(const edr_event &e, const std::shared_ptr<ProcNode> &n) const;
    void decay_to(const std::shared_ptr<ProcNode> &n, double now);
    void recompute(const std::shared_ptr<ProcNode> &n);
    void add_evidence(const std::shared_ptr<ProcNode> &n, int cat, double amount, double now);
    void backprop(const std::shared_ptr<ProcNode> &n, int cat, double amount, int depth, double now);
    std::string active_stages(const std::shared_ptr<ProcNode> &n) const;
    std::string compute_origin(const std::shared_ptr<ProcNode> &n) const;
    void update_watchlist(const std::shared_ptr<ProcNode> &n);
    void log_masquerade(const std::shared_ptr<ProcNode> &n, const char *new_name, bool susp);
    void log_alert(const std::string &s);
    SnapNode build_snap(const std::shared_ptr<ProcNode> &n) const;
    void collect_top(const std::shared_ptr<ProcNode> &n, std::vector<TopEntry> &out) const;
    void gc_sweep(double now_sec);
    void mitigate(std::shared_ptr<ProcNode> n);
    void detach_from_parent(const std::shared_ptr<ProcNode> &n);
};

#endif