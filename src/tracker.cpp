#include "tracker.h"
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <chrono>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

static double now_sec() {
    using namespace std::chrono;
    return duration<double>(steady_clock::now().time_since_epoch()).count();
}

static double ns_to_sec(std::uint64_t ns) { return static_cast<double>(ns) / 1e9; }

Tracker::Tracker(EngineCfg cfg, std::uint32_t own_pgid)
    : cfg_(std::move(cfg)), own_pgid_(own_pgid) {}

std::string Tracker::mk_uid(std::uint32_t tgid, std::uint64_t ts_ns) const {
    return std::to_string(tgid) + "_" + std::to_string(ts_ns);
}

std::string Tracker::ev_key(std::uint8_t t) const {
    switch (t) {
        case EV_FORK: return "ev_fork";
        case EV_EXIT: return "ev_exit";
        case EV_EXEC: return "ev_exec";
        case EV_MPROTECT_WX: return "ev_mprotect_wx";
        case EV_MEMFD_CREATE: return "ev_memfd_create";
        case EV_PRCTL_RENAME: return "ev_prctl_rename";
        case EV_PTRACE: return "ev_ptrace";
        case EV_COMMIT_CREDS: return "ev_commit_creds";
        case EV_UNSHARE: return "ev_unshare";
        case EV_SEC_BPF: return "ev_sec_bpf";
        case EV_TCP_CONNECT: return "ev_tcp_connect";
    }
    return "ev_unknown";
}

std::shared_ptr<ProcNode> Tracker::lookup_by_pid(std::uint32_t tgid) {
    auto it = pid_to_uid_.find(tgid);
    if (it == pid_to_uid_.end()) return nullptr;
    auto nit = nodes_.find(it->second);
    if (nit == nodes_.end()) return nullptr;
    return nit->second;
}

std::shared_ptr<ProcNode> Tracker::fork_node(const edr_event &e) {
    auto pit = pid_to_uid_.find(e.tgid);
    if (pit != pid_to_uid_.end()) {
        auto old = nodes_.find(pit->second);
        if (old != nodes_.end()) {
            old->second->is_dead = true;
            old->second->died_ts = ns_to_sec(e.ts_ns);
        }
    }
    auto n = std::make_shared<ProcNode>();
    n->uid = mk_uid(e.tgid, e.ts_ns);
    n->pid = e.pid;
    n->tgid = e.tgid;
    n->ppid = e.ppid;
    n->pgid = e.pgid;
    n->owner_uid = e.uid;
    n->ns_inum = e.ns_inum;
    std::memcpy(n->comm, e.comm, MAX_COMM);
    n->created_ts = ns_to_sec(e.ts_ns);
    n->last_ev_ts = n->created_ts;
    auto par = lookup_by_pid(e.ppid);
    if (par) {
        n->parent = par;
        par->children.push_back(n);
    } else {
        roots_.push_back(n);
    }
    nodes_[n->uid] = n;
    pid_to_uid_[e.tgid] = n->uid;
    return n;
}

std::shared_ptr<ProcNode> Tracker::ensure_node(const edr_event &e) {
    auto n = lookup_by_pid(e.tgid);
    if (n) return n;
    auto sn = std::make_shared<ProcNode>();
    sn->uid = mk_uid(e.tgid, e.ts_ns);
    sn->pid = e.pid;
    sn->tgid = e.tgid;
    sn->ppid = e.ppid;
    sn->pgid = e.pgid;
    sn->owner_uid = e.uid;
    sn->ns_inum = e.ns_inum;
    std::memcpy(sn->comm, e.comm, MAX_COMM);
    sn->created_ts = ns_to_sec(e.ts_ns);
    sn->last_ev_ts = sn->created_ts;
    auto par = lookup_by_pid(e.ppid);
    if (par) {
        sn->parent = par;
        par->children.push_back(sn);
    } else {
        roots_.push_back(sn);
    }
    nodes_[sn->uid] = sn;
    pid_to_uid_[e.tgid] = sn->uid;
    return sn;
}

double Tracker::ctx_mult(const edr_event &e, const std::shared_ptr<ProcNode> &n) const {
    double m = 1.0;
    if (e.uid == 0) m *= cfg_.ctx_uid0;
    if (n && n->ns_inum != 0 && e.ns_inum != 0 && n->ns_inum != e.ns_inum) m *= cfg_.ctx_ns;
    if (n) {
        double age = ns_to_sec(e.ts_ns) - n->created_ts;
        if (age >= 0.0 && age < 1.0) m *= cfg_.ctx_short;
    }
    return m;
}

void Tracker::apply_spike(std::shared_ptr<ProcNode> n, double spike, double ts_sec) {
    if (!n) return;
    double dt = ts_sec - n->last_ev_ts;
    if (dt > 0.0) {
        n->raw_score = MathEng::apply_decay(n->raw_score, dt, cfg_.lambda);
    }
    n->raw_score = MathEng::clamp_score(n->raw_score + spike, cfg_.raw_score_cap);
    n->last_ev_ts = ts_sec;
    n->decayed_score = n->raw_score;
    n->risk_pct = MathEng::risk_pct(n->raw_score, cfg_.k, cfg_.x_0);
}

void Tracker::backprop(std::shared_ptr<ProcNode> n, double spike, int depth) {
    if (!n || depth >= cfg_.backprop_max_depth) return;
    auto p = n->parent.lock();
    if (!p) return;
    double propagated = spike * cfg_.backprop_factor;
    if (propagated < 0.05) return;
    double t = now_sec();
    apply_spike(p, propagated, t);
    backprop(p, propagated, depth + 1);
}

void Tracker::ingest(const edr_event &e) {
    ev_count_.fetch_add(1);
    std::unique_lock<std::shared_mutex> lk(g_lock_);
    std::shared_ptr<ProcNode> n;
    if (e.ev_type == EV_FORK) {
        n = fork_node(e);
    } else if (e.ev_type == EV_EXIT) {
        n = lookup_by_pid(e.tgid);
        if (n) {
            n->is_dead = true;
            n->died_ts = ns_to_sec(e.ts_ns);
        }
    } else {
        n = ensure_node(e);
        if (n && e.ev_type == EV_EXEC) {
            std::memcpy(n->comm, e.comm, MAX_COMM);
        }
        if (n && e.ev_type == EV_PRCTL_RENAME) {
            char nn[MAX_COMM] = {0};
            std::memcpy(nn, e.data.rename.new_name, MAX_COMM - 1);
            if (nn[0] && std::memcmp(nn, n->comm, MAX_COMM) != 0) {
                char msg[192];
                std::snprintf(msg, sizeof(msg),
                    "[%u] MASQUERADE '%s' -> '%s'", n->pid, n->comm, nn);
                alerts_.push_back(msg);
                if (alerts_.size() > 200) alerts_.pop_front();
            }
        }
    }
    if (!n) return;
    std::string k = ev_key(e.ev_type);
    double w = MathEng::weight_for(cfg_, k);
    if (w <= 0.0) return;
    double c = ctx_mult(e, n);
    double spike = w * c;
    double ts = ns_to_sec(e.ts_ns);
    apply_spike(n, spike, ts);
    backprop(n, spike, 0);
    if (spike >= 40.0) {
        char msg[192];
        std::snprintf(msg, sizeof(msg), "[%u] %s spike=%.1f risk=%.2f",
            n->pid, k.c_str(), spike, n->risk_pct);
        alerts_.push_back(msg);
        if (alerts_.size() > 200) alerts_.pop_front();
    }
}

void Tracker::mitigate(std::shared_ptr<ProcNode> n) {
    if (!n) return;
    std::uint32_t pgid = n->pgid;
    if (pgid <= 1) return;
    if (pgid == own_pgid_) return;
    if (::kill(-static_cast<pid_t>(pgid), SIGKILL) == 0) {
        kills_.fetch_add(1);
        char msg[192];
        std::snprintf(msg, sizeof(msg),
            "[KILL] pgid=%u pid=%u comm=%s risk=%.2f", pgid, n->pid, n->comm, n->risk_pct);
        alerts_.push_back(msg);
        if (alerts_.size() > 200) alerts_.pop_front();
        n->is_dead = true;
        n->died_ts = now_sec();
    }
}

void Tracker::detach_from_parent(const std::shared_ptr<ProcNode> &n) {
    if (!n) return;
    auto p = n->parent.lock();
    if (!p) {
        auto it = std::find(roots_.begin(), roots_.end(), n);
        if (it != roots_.end()) roots_.erase(it);
        return;
    }
    auto &v = p->children;
    v.erase(std::remove(v.begin(), v.end(), n), v.end());
}

void Tracker::gc_sweep(double now_s) {
    std::vector<std::string> to_erase;
    for (auto &kv : nodes_) {
        auto &n = kv.second;
        if (!n) continue;
        double dt = now_s - n->last_ev_ts;
        if (dt > 0.0) {
            n->raw_score = MathEng::apply_decay(n->raw_score, dt, cfg_.lambda);
            n->decayed_score = n->raw_score;
            n->risk_pct = MathEng::risk_pct(n->raw_score, cfg_.k, cfg_.x_0);
            n->last_ev_ts = now_s;
        }
        if (n->is_dead) {
            double ddt = now_s - n->died_ts;
            if (n->risk_pct < cfg_.gc_tomb_risk_floor && ddt > cfg_.gc_dead_ttl_sec) {
                to_erase.push_back(n->uid);
            }
        }
    }
    for (auto &u : to_erase) {
        auto it = nodes_.find(u);
        if (it == nodes_.end()) continue;
        auto n = it->second;
        detach_from_parent(n);
        for (auto &p : pid_to_uid_) {
            if (p.second == u) { pid_to_uid_.erase(p.first); break; }
        }
        nodes_.erase(it);
    }
}

void Tracker::tick() {
    double t = now_sec();
    std::vector<std::shared_ptr<ProcNode>> kill_list;
    {
        std::unique_lock<std::shared_mutex> lk(g_lock_);
        for (auto &kv : nodes_) {
            auto &n = kv.second;
            if (!n || n->is_dead) continue;
            double dt = t - n->last_ev_ts;
            if (dt > 0.0) {
                n->raw_score = MathEng::apply_decay(n->raw_score, dt, cfg_.lambda);
                n->decayed_score = n->raw_score;
                n->risk_pct = MathEng::risk_pct(n->raw_score, cfg_.k, cfg_.x_0);
                n->last_ev_ts = t;
            }
            if (n->risk_pct >= cfg_.kill_threshold) {
                kill_list.push_back(n);
            }
        }
        for (auto &n : kill_list) mitigate(n);
        gc_sweep(t);
    }
}

SnapNode Tracker::build_snap(const std::shared_ptr<ProcNode> &n) const {
    SnapNode s;
    s.pid = n->pid;
    s.comm = std::string(n->comm, ::strnlen(n->comm, MAX_COMM));
    s.risk_pct = n->risk_pct;
    s.raw_score = n->raw_score;
    s.is_dead = n->is_dead;
    for (auto &c : n->children) {
        if (!c) continue;
        s.children.push_back(build_snap(c));
    }
    return s;
}

void Tracker::collect_top(const std::shared_ptr<ProcNode> &n, std::vector<TopEntry> &out) const {
    if (!n) return;
    if (!n->is_dead) {
        TopEntry e;
        e.pid = n->pid;
        e.comm = std::string(n->comm, ::strnlen(n->comm, MAX_COMM));
        e.risk_pct = n->risk_pct;
        out.push_back(e);
    }
    for (auto &c : n->children) collect_top(c, out);
}

Snapshot Tracker::snapshot() const {
    Snapshot s;
    std::shared_lock<std::shared_mutex> lk(g_lock_);
    for (auto &r : roots_) {
        if (!r) continue;
        s.roots.push_back(build_snap(r));
    }
    std::vector<TopEntry> all;
    for (auto &r : roots_) collect_top(r, all);
    std::sort(all.begin(), all.end(),
        [](const TopEntry &a, const TopEntry &b) { return a.risk_pct > b.risk_pct; });
    if (all.size() > 3) all.resize(3);
    s.top3 = std::move(all);
    s.total_nodes = nodes_.size();
    for (auto &kv : nodes_) if (kv.second && !kv.second->is_dead) s.live_nodes++;
    return s;
}

std::vector<std::string> Tracker::tail_alerts(std::size_t n) const {
    std::vector<std::string> out;
    std::lock_guard<std::mutex> lk(alert_lock_);
    std::size_t sz = alerts_.size();
    std::size_t start = (sz > n) ? (sz - n) : 0;
    for (std::size_t i = start; i < sz; i++) out.push_back(alerts_[i]);
    return out;
}

void Tracker::push_alert(const std::string &s) {
    std::lock_guard<std::mutex> lk(alert_lock_);
    alerts_.push_back(s);
    if (alerts_.size() > 200) alerts_.pop_front();
}

void Tracker::stop() { running_.store(false); }