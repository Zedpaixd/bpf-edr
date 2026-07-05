#include "tracker.h"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

static constexpr double WATCH_THRESHOLD = 0.40;
static constexpr std::size_t WATCH_MAX = 20;
static constexpr std::size_t MASQ_CAP = 100;

static double now_sec() {
    using namespace std::chrono;
    return duration<double>(steady_clock::now().time_since_epoch()).count();
}
static double ns_to_sec(std::uint64_t ns) { return static_cast<double>(ns) / 1e9; }

static std::string now_hms_ms() {
    using namespace std::chrono;
    auto now = system_clock::now();
    std::time_t t = system_clock::to_time_t(now);
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    std::tm tmv;
    localtime_r(&t, &tmv);
    char b[16];
    std::snprintf(b, sizeof(b), "%02d:%02d:%02d.%03d",
        tmv.tm_hour, tmv.tm_min, tmv.tm_sec, (int)ms.count());
    return b;
}

static int ev_category(std::uint8_t t) {
    switch (t) {
        case EV_FORK: case EV_EXIT: return CAT_LIFECYCLE;
        case EV_EXEC: case EV_MEMFD_CREATE: return CAT_EXECUTION;
        case EV_MPROTECT_WX: case EV_PTRACE: return CAT_MEMORY;
        case EV_COMMIT_CREDS: case EV_UNSHARE: return CAT_PRIVILEGE;
        case EV_PRCTL_RENAME: case EV_SEC_BPF: return CAT_EVASION;
        case EV_TCP_CONNECT: return CAT_C2;
    }
    return CAT_LIFECYCLE;
}

Tracker::Tracker(EngineCfg cfg, std::uint32_t own_pgid, std::uint32_t own_pid)
    : cfg_(std::move(cfg)), own_pgid_(own_pgid), own_pid_(own_pid) {
    start_ts_ = now_sec();
    if (cfg_.exempt_comms.empty()) {
        cfg_.exempt_comms = { "bash", "sh", "dash", "zsh", "fish", "ksh",
                              "ash", "sudo", "su", "login", "systemd", "init" };
    }
}

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

bool Tracker::self_pid(std::uint32_t pid, std::uint32_t pgid) const {
    return pid == own_pid_ || pgid == own_pgid_;
}

bool Tracker::is_self(const edr_event &e) const {
    return e.tgid == own_pid_ || self_pid(e.pid, e.pgid);
}

bool Tracker::is_exempt_comm(const char *nm) const {
    if (!nm || !nm[0]) return false;
    for (auto &pat : cfg_.exempt_comms)
        if (std::strncmp(nm, pat.c_str(), MAX_COMM) == 0) return true;
    return false;
}

bool Tracker::is_masq_name(const char *nm) const {
    if (!nm || !nm[0]) return false;
    for (auto &pat : cfg_.masq_names)
        if (std::strncmp(nm, pat.c_str(), pat.size()) == 0) return true;
    return false;
}

void Tracker::log_alert(const std::string &s) {
    std::lock_guard<std::mutex> lk(alert_lock_);
    alerts_.push_back("[" + now_hms_ms() + "] " + s);
    if (alerts_.size() > 200) alerts_.pop_front();
}

void Tracker::seed_from_proc() {
    DIR *d = opendir("/proc");
    if (!d) return;
    struct SEntry { std::uint32_t pid, ppid, pgid; std::string comm; };
    std::vector<SEntry> entries;
    struct dirent *de;
    while ((de = readdir(d)) != nullptr) {
        char *end;
        long p = std::strtol(de->d_name, &end, 10);
        if (*end != '\0' || p <= 0) continue;
        char path[64];
        std::snprintf(path, sizeof(path), "/proc/%ld/stat", p);
        int fd = ::open(path, O_RDONLY);
        if (fd < 0) continue;
        char buf[512];
        ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
        ::close(fd);
        if (n <= 0) continue;
        buf[n] = 0;
        char *lp = std::strchr(buf, '(');
        char *rp = std::strrchr(buf, ')');
        if (!lp || !rp || lp >= rp) continue;
        SEntry se;
        se.pid = static_cast<std::uint32_t>(p);
        std::size_t clen = static_cast<std::size_t>(rp - lp - 1);
        if (clen >= MAX_COMM) clen = MAX_COMM - 1;
        se.comm.assign(lp + 1, clen);
        char state; unsigned ppid = 0, pgid = 0;
        if (std::sscanf(rp + 1, " %c %u %u", &state, &ppid, &pgid) != 3) continue;
        se.ppid = ppid; se.pgid = pgid;
        entries.push_back(std::move(se));
    }
    closedir(d);

    std::unique_lock<std::shared_mutex> lk(g_lock_);
    double t = now_sec();
    for (auto &se : entries) {
        auto n = std::make_shared<ProcNode>();
        n->uid = std::to_string(se.pid) + "_seed";
        n->pid = se.pid; n->tgid = se.pid; n->ppid = se.ppid; n->pgid = se.pgid;
        n->is_new = false;
        std::size_t clen = std::min(se.comm.size(), (std::size_t)(MAX_COMM - 1));
        std::memcpy(n->comm, se.comm.data(), clen);
        n->comm[clen] = 0;
        n->exempt = self_pid(se.pid, se.pgid) || is_exempt_comm(n->comm);
        n->created_ts = t; n->last_ev_ts = t; n->last_score_ts = t;
        nodes_[n->uid] = n;
        pid_to_uid_[se.pid] = n->uid;
    }
    for (auto &se : entries) {
        auto it = pid_to_uid_.find(se.pid);
        if (it == pid_to_uid_.end()) continue;
        auto n = nodes_[it->second];
        if (se.ppid > 0) {
            auto pit = pid_to_uid_.find(se.ppid);
            if (pit != pid_to_uid_.end() && pit->second != n->uid) {
                auto p = nodes_[pit->second];
                n->parent = p; p->children.push_back(n);
                continue;
            }
        }
        roots_.push_back(n);
    }
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
    n->pid = e.pid; n->tgid = e.tgid; n->ppid = e.ppid; n->pgid = e.pgid;
    n->owner_uid = e.uid; n->ns_inum = e.ns_inum;
    n->is_new = true;
    std::memcpy(n->comm, e.comm, MAX_COMM);
    n->exempt = self_pid(e.pid, e.pgid) || is_exempt_comm(n->comm);
    double t = ns_to_sec(e.ts_ns);
    n->created_ts = t; n->last_ev_ts = t; n->last_score_ts = t;
    auto par = lookup_by_pid(e.ppid);
    if (par) { n->parent = par; par->children.push_back(n); }
    else roots_.push_back(n);
    nodes_[n->uid] = n;
    pid_to_uid_[e.tgid] = n->uid;
    return n;
}

std::shared_ptr<ProcNode> Tracker::ensure_node(const edr_event &e) {
    auto n = lookup_by_pid(e.tgid);
    if (n) return n;
    auto sn = std::make_shared<ProcNode>();
    sn->uid = mk_uid(e.tgid, e.ts_ns);
    sn->pid = e.pid; sn->tgid = e.tgid; sn->ppid = e.ppid; sn->pgid = e.pgid;
    sn->owner_uid = e.uid; sn->ns_inum = e.ns_inum;
    sn->is_new = false;
    std::memcpy(sn->comm, e.comm, MAX_COMM);
    sn->exempt = self_pid(e.pid, e.pgid) || is_exempt_comm(sn->comm);
    double t = ns_to_sec(e.ts_ns);
    sn->created_ts = t; sn->last_ev_ts = t; sn->last_score_ts = t;
    auto par = lookup_by_pid(e.ppid);
    if (par) { sn->parent = par; par->children.push_back(sn); }
    else roots_.push_back(sn);
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

void Tracker::decay_to(const std::shared_ptr<ProcNode> &n, double now) {
    if (!n) return;
    double dt = now - n->last_score_ts;
    if (dt <= 0.0) return;
    for (int c = 0; c < CAT_COUNT; c++)
        n->cat_accum[c] = MathEng::decay_accum(n->cat_accum[c], dt, cfg_.cats[c].half_life);
    n->last_score_ts = now;
}

void Tracker::recompute(const std::shared_ptr<ProcNode> &n) {
    if (!n) return;
    double S = cfg_.prior_logodds;
    if (!n->is_new) S += cfg_.seeded_prior_extra;
    int n_active = 0;
    for (int c = 0; c < CAT_COUNT; c++) {
        double contrib = MathEng::cat_contrib(n->cat_accum[c], cfg_.cats[c].max_llr, cfg_.cats[c].scale);
        S += contrib;
        if (contrib >= cfg_.active_floor) n_active++;
    }
    if (n_active >= 2) S += cfg_.corrob_coeff * (n_active - 1);
    n->logodds = S;
    n->risk_pct = MathEng::sigmoid_stable(S);
    if (n->risk_pct > n->peak_risk_pct) n->peak_risk_pct = n->risk_pct;
}

void Tracker::add_evidence(const std::shared_ptr<ProcNode> &n, int cat, double amount, double now) {
    if (!n || n->exempt || amount <= 0.0) return;
    decay_to(n, now);
    n->cat_accum[cat] += amount;
    n->last_ev_ts = now;
    recompute(n);
    update_watchlist(n);
}

void Tracker::backprop(const std::shared_ptr<ProcNode> &n, int cat, double amount, int depth, double now) {
    if (!n || depth >= cfg_.backprop_max_depth) return;
    auto p = n->parent.lock();
    if (!p || p->exempt) return;
    double prop = amount * cfg_.backprop_factor;
    if (prop < 0.05) return;
    add_evidence(p, cat, prop, now);
    backprop(p, cat, prop, depth + 1, now);
}

std::string Tracker::active_stages(const std::shared_ptr<ProcNode> &n) const {
    static const char L[CAT_COUNT] = { 'L', 'X', 'M', 'P', 'E', 'C' };
    std::string s;
    for (int c = 0; c < CAT_COUNT; c++) {
        double contrib = MathEng::cat_contrib(n->cat_accum[c], cfg_.cats[c].max_llr, cfg_.cats[c].scale);
        if (contrib >= cfg_.active_floor) s += L[c];
    }
    return s;
}

std::string Tracker::compute_origin(const std::shared_ptr<ProcNode> &n) const {
    std::string origin(n->comm, ::strnlen(n->comm, MAX_COMM));
    auto cur = n->parent.lock();
    while (cur) {
        if (!cur->exempt) origin.assign(cur->comm, ::strnlen(cur->comm, MAX_COMM));
        cur = cur->parent.lock();
    }
    return origin;
}

void Tracker::update_watchlist(const std::shared_ptr<ProcNode> &n) {
    if (!n || n->exempt || n->peak_risk_pct < WATCH_THRESHOLD) return;
    auto it = watchlist_.find(n->uid);
    if (it == watchlist_.end()) {
        if (watchlist_.size() >= WATCH_MAX) {
            auto lowest = watchlist_.begin();
            for (auto i = watchlist_.begin(); i != watchlist_.end(); ++i)
                if (i->second.peak_risk_pct < lowest->second.peak_risk_pct) lowest = i;
            if (lowest->second.peak_risk_pct >= n->peak_risk_pct) return;
            watchlist_.erase(lowest);
        }
        WatchEntry w;
        w.uid = n->uid; w.pid = n->pid;
        w.first_tstr = now_hms_ms();
        w.comm.assign(n->comm, ::strnlen(n->comm, MAX_COMM));
        w.origin = compute_origin(n);
        w.stages = active_stages(n);
        w.peak_risk_pct = n->peak_risk_pct;
        w.current_risk_pct = n->risk_pct;
        w.child_count = n->children.size();
        w.is_dead = n->is_dead;
        watchlist_[n->uid] = std::move(w);
    } else {
        it->second.peak_risk_pct = n->peak_risk_pct;
        it->second.current_risk_pct = n->risk_pct;
        it->second.child_count = n->children.size();
        it->second.is_dead = n->is_dead;
        it->second.stages = active_stages(n);
        it->second.comm.assign(n->comm, ::strnlen(n->comm, MAX_COMM));
        it->second.origin = compute_origin(n);
    }
}

void Tracker::log_masquerade(const std::shared_ptr<ProcNode> &n, const char *new_name, bool susp) {
    if (!n || !new_name || !new_name[0]) return;
    if (std::strncmp(new_name, n->comm, MAX_COMM) == 0) return;
    MasqEvent m;
    m.tstr = now_hms_ms();
    m.pid = n->pid;
    m.old_comm.assign(n->comm, ::strnlen(n->comm, MAX_COMM));
    m.new_comm.assign(new_name, ::strnlen(new_name, MAX_COMM));
    m.risk_pct = n->risk_pct;
    m.suspicious = susp;
    masq_events_.push_back(m);
    if (masq_events_.size() > MASQ_CAP) masq_events_.pop_front();
    if (susp) {
        char msg[192];
        std::snprintf(msg, sizeof(msg), "[%u] MASQUERADE '%s' -> '%s'",
                      n->pid, m.old_comm.c_str(), m.new_comm.c_str());
        log_alert(msg);
    }
}

void Tracker::ingest(const edr_event &e) {
    ev_count_.fetch_add(1);
    std::unique_lock<std::shared_mutex> lk(g_lock_);
    std::shared_ptr<ProcNode> n;
    bool prctl_score = false;

    if (e.ev_type == EV_FORK) {
        n = fork_node(e);
    } else if (e.ev_type == EV_EXIT) {
        n = lookup_by_pid(e.tgid);
        if (n) {
            n->is_dead = true;
            n->died_ts = ns_to_sec(e.ts_ns);
            auto wit = watchlist_.find(n->uid);
            if (wit != watchlist_.end()) wit->second.is_dead = true;
        }
        return;
    } else {
        n = ensure_node(e);
        if (n && e.ev_type == EV_EXEC) {
            std::memcpy(n->comm, e.comm, MAX_COMM);
            n->exempt = self_pid(n->pid, n->pgid) || is_exempt_comm(n->comm);
        }
        if (n && e.ev_type == EV_PRCTL_RENAME && !n->exempt) {
            char nn[MAX_COMM] = {0};
            std::memcpy(nn, e.data.rename.new_name, MAX_COMM - 1);
            prctl_score = is_masq_name(nn);
            log_masquerade(n, nn, prctl_score);
        }
    }
    if (!n || n->exempt) return;

    std::string k = ev_key(e.ev_type);
    if (e.ev_type == EV_PRCTL_RENAME && !prctl_score) return;
    double base = MathEng::llr_for(cfg_, k);
    if (base <= 0.0) return;

    double c = ctx_mult(e, n);
    double amount = base * c;
    int cat = ev_category(e.ev_type);
    double t = ns_to_sec(e.ts_ns);
    if (t <= 0.0) t = now_sec();

    add_evidence(n, cat, amount, t);
    backprop(n, cat, amount, 0, now_sec());

    if (base >= 1.5) {
        char msg[192];
        std::snprintf(msg, sizeof(msg), "[%u] %s %s llr=%.2f risk=%.1f%% st=%s",
            n->pid, n->comm, k.c_str(), amount, n->risk_pct * 100.0,
            active_stages(n).c_str());
        log_alert(msg);
    }
}

void Tracker::mitigate(std::shared_ptr<ProcNode> n) {
    if (!n || n->exempt || n->kill_flagged) return;
    std::uint32_t pgid = n->pgid;
    if (pgid <= 1) return;
    if (pgid == own_pgid_) return;
    n->kill_flagged = true;
    kills_.fetch_add(1);
    char msg[192];
    std::snprintf(msg, sizeof(msg),
        "[WOULD-KILL] pgid=%u pid=%u comm=%s risk=%.1f%% (kill disabled)",
        pgid, n->pid, n->comm, n->risk_pct * 100.0);
    log_alert(msg);
    // TO RE-ENABLE MITIGATION, uncomment:
    // if (::kill(-static_cast<pid_t>(pgid), SIGKILL) == 0) {
    //     n->is_dead = true; n->died_ts = now_sec();
    //     auto wit = watchlist_.find(n->uid);
    //     if (wit != watchlist_.end()) wit->second.is_dead = true;
    // }
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
        if (!n || !n->is_dead) continue;
        if (n->peak_risk_pct >= cfg_.gc_forensic_keep) continue;
        double ttl = cfg_.gc_base_ttl_sec + cfg_.gc_peak_ttl_coeff * n->peak_risk_pct;
        double ddt = now_s - n->died_ts;
        if (n->risk_pct < cfg_.gc_tomb_risk_floor && ddt > ttl)
            to_erase.push_back(n->uid);
    }
    for (auto &u : to_erase) {
        auto it = nodes_.find(u);
        if (it == nodes_.end()) continue;
        detach_from_parent(it->second);
        for (auto pit = pid_to_uid_.begin(); pit != pid_to_uid_.end(); ) {
            if (pit->second == u) pit = pid_to_uid_.erase(pit);
            else ++pit;
        }
        nodes_.erase(it);
    }
}

void Tracker::tick() {
    double t = now_sec();
    bool warm = (t - start_ts_) >= cfg_.warmup_sec;
    std::vector<std::shared_ptr<ProcNode>> kill_list;
    {
        std::unique_lock<std::shared_mutex> lk(g_lock_);
        for (auto &kv : nodes_) {
            auto &n = kv.second;
            if (!n || n->is_dead || n->exempt) continue;
            decay_to(n, t);
            recompute(n);
            auto wit = watchlist_.find(n->uid);
            if (wit != watchlist_.end()) {
                wit->second.current_risk_pct = n->risk_pct;
                wit->second.child_count = n->children.size();
                wit->second.stages = active_stages(n);
            }
            if (n->risk_pct >= cfg_.kill_threshold) {
                if (n->above_since <= 0.0) n->above_since = t;
                if (warm && (t - n->above_since) >= cfg_.dwell_sec)
                    kill_list.push_back(n);
            } else {
                n->above_since = 0.0;
            }
        }
        for (auto &n : kill_list) mitigate(n);
        gc_sweep(t);
    }
}

SnapNode Tracker::build_snap(const std::shared_ptr<ProcNode> &n) const {
    SnapNode s;
    s.pid = n->pid;
    s.comm.assign(n->comm, ::strnlen(n->comm, MAX_COMM));
    s.risk_pct = n->risk_pct;
    s.is_dead = n->is_dead;
    s.is_new = n->is_new;
    s.exempt = n->exempt;
    for (auto &c : n->children) if (c) s.children.push_back(build_snap(c));
    return s;
}

void Tracker::collect_top(const std::shared_ptr<ProcNode> &n, std::vector<TopEntry> &out) const {
    if (!n) return;
    if (!n->is_dead && !n->exempt) {
        TopEntry e;
        e.pid = n->pid;
        e.comm.assign(n->comm, ::strnlen(n->comm, MAX_COMM));
        e.risk_pct = n->risk_pct;
        out.push_back(e);
    }
    for (auto &c : n->children) collect_top(c, out);
}

Snapshot Tracker::snapshot() const {
    Snapshot s;
    std::shared_lock<std::shared_mutex> lk(g_lock_);
    for (auto &r : roots_) if (r) s.roots.push_back(build_snap(r));
    std::vector<TopEntry> all;
    for (auto &r : roots_) collect_top(r, all);
    std::sort(all.begin(), all.end(),
        [](const TopEntry &a, const TopEntry &b) { return a.risk_pct > b.risk_pct; });
    if (all.size() > 3) all.resize(3);
    s.top3 = std::move(all);
    s.total_nodes = nodes_.size();
    for (auto &kv : nodes_) {
        if (!kv.second) continue;
        if (!kv.second->is_dead) s.live_nodes++;
        if (kv.second->is_new && !kv.second->is_dead && !kv.second->exempt) s.new_nodes++;
    }
    std::size_t mn = std::min<std::size_t>(8, masq_events_.size());
    for (std::size_t i = masq_events_.size() - mn; i < masq_events_.size(); i++)
        s.masq_events.push_back(masq_events_[i]);
    for (auto &kv : watchlist_) s.watchlist.push_back(kv.second);
    std::sort(s.watchlist.begin(), s.watchlist.end(),
        [](const WatchEntry &a, const WatchEntry &b) { return a.peak_risk_pct > b.peak_risk_pct; });
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

void Tracker::push_alert(const std::string &s) { log_alert(s); }

void Tracker::stop() { running_.store(false); }