#include "ui.h"
#include <ftxui/component/component.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/mouse.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/color.hpp>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

using namespace ftxui;

struct FlatRow {
    int depth;
    std::uint32_t pid;
    std::string comm;
    double risk_pct;
    double badge_risk;
    bool is_dead;
    bool is_new;
    bool is_anchor;
    bool exempt;
    bool frozen;
    bool blocked;
};

Ui::Ui(std::shared_ptr<Tracker> t) : tr_(std::move(t)) {}
void Ui::stop() { stop_.store(true); }

static Color risk_color(double r) {
    if (r < 0.20) return Color::Green;
    if (r < 0.75) return Color::Yellow;
    return Color::Red;
}
static std::string fmt_pct(double r) {
    char b[16];
    std::snprintf(b, sizeof(b), "%5.1f%%", r * 100.0);
    return b;
}
static std::string hclip(const std::string &s, int off) {
    if (off <= 0) return s;
    if ((std::size_t)off >= s.size()) return std::string();
    return s.substr((std::size_t)off);
}

static Element wrap_indent(const std::string &s, int width, int indent, Color c, bool bold_on) {
    if (width < 8) width = 8;
    if (indent < 0) indent = 0;
    if (indent > width - 4) indent = width - 4;
    Elements lines;
    std::string pad(indent, ' ');
    std::size_t pos = 0;
    bool first = true;
    while (pos < s.size()) {
        int avail = first ? width : (width - indent);
        if (avail < 1) avail = 1;
        std::string chunk = s.substr(pos, (std::size_t)avail);
        pos += chunk.size();
        std::string full = first ? chunk : (pad + chunk);
        Element e = text(full) | color(c);
        if (bold_on) e = e | bold;
        lines.push_back(e);
        first = false;
    }
    if (lines.empty()) {
        Element e = text("") | color(c);
        lines.push_back(e);
    }
    return vbox(std::move(lines));
}

static void collapse_walk(const SnapNode &n, int depth, bool parent_exempt,
                          bool anchor_used, std::vector<FlatRow> &out) {
    if (!n.exempt) {
        out.push_back({depth, n.pid, n.comm, n.risk_pct, n.badge_risk,
                       n.is_dead, n.is_new, false, false, n.frozen, n.blocked});
        for (auto &c : n.children) collapse_walk(c, depth + 1, false, anchor_used, out);
    } else {
        bool anchor = (!anchor_used && !parent_exempt);
        if (anchor) {
            out.push_back({depth, n.pid, n.comm, n.risk_pct, 0.0,
                           n.is_dead, n.is_new, true, true, false, false});
            for (auto &c : n.children) collapse_walk(c, depth + 1, true, true, out);
        } else {
            for (auto &c : n.children) collapse_walk(c, depth, true, anchor_used, out);
        }
    }
}

static void newonly_walk(const SnapNode &n, std::vector<FlatRow> &out) {
    if (n.is_new && !n.exempt)
        out.push_back({0, n.pid, n.comm, n.risk_pct, n.badge_risk,
                       n.is_dead, true, false, false, n.frozen, n.blocked});
    for (auto &c : n.children) newonly_walk(c, out);
}

static std::vector<FlatRow> build_flat(const Snapshot &snap, bool new_only) {
    std::vector<FlatRow> rows;
    if (new_only) for (auto &r : snap.roots) newonly_walk(r, rows);
    else          for (auto &r : snap.roots) collapse_walk(r, 0, false, false, rows);
    return rows;
}

static Element make_row(const FlatRow &r, bool selected, int hoff) {
    std::string prefix(r.depth * 2, ' ');
    prefix += r.is_new ? "* " : "  ";
    std::string label = prefix + "[" + std::to_string(r.pid) + "] " + r.comm
                        + " - " + fmt_pct(r.risk_pct);
    if (r.blocked) label += " (BLOCKED)";
    else if (r.frozen) label += " (FROZEN)";
    else if (r.is_dead) label += " (dead)";
    if (r.is_anchor) label += "  <shell>";
    Color c;
    if (r.blocked)        c = Color::Magenta;
    else if (r.frozen)    c = Color::Cyan;
    else if (r.is_dead)   c = r.risk_pct >= 0.20 ? Color::Red : Color::GrayDark;
    else if (r.is_anchor) c = Color::GrayDark;
    else if (r.exempt)    c = Color::GrayLight;
    else                  c = risk_color(r.risk_pct);

    Elements parts;
    Element base = text(hclip(label, hoff)) | color(c);
    if (r.frozen || r.blocked) base = base | bold;
    parts.push_back(base);
    if (r.badge_risk > 0.05) {
        std::string chip = " sub " + fmt_pct(r.badge_risk) + " ";
        Element ce = text(chip) | bgcolor(risk_color(r.badge_risk)) | color(Color::Black) | bold;
        if (r.is_dead) ce = ce | dim;
        parts.push_back(ce);
    }
    Element el = hbox(std::move(parts));
    if (selected) el = el | inverted | focus;
    return el;
}

static Element build_tree_pane(const Snapshot &snap, int &sel, bool new_only, int hoff) {
    std::vector<FlatRow> rows = build_flat(snap, new_only);
    if (rows.empty()) {
        return window(text(" Lineage & State ") | bold,
                      vbox({ text(" (no processes match filter) ") | dim | center | flex }));
    }
    if (sel < 0) sel = 0;
    if (sel >= (int)rows.size()) sel = (int)rows.size() - 1;
    Elements list;
    list.reserve(rows.size());
    for (int i = 0; i < (int)rows.size(); i++) list.push_back(make_row(rows[i], i == sel, hoff));
    char meta[224];
    std::snprintf(meta, sizeof(meta),
        " %s | row %d/%zu | live=%zu new=%zu frozen=%zu | H%+d ",
        new_only ? "NEW ONLY (a: all)" : "ALL (n: new only)",
        sel + 1, rows.size(), snap.live_nodes, snap.new_nodes, snap.frozen_count, hoff);
    return window(text(" Lineage & State ") | bold,
                  vbox({ text(meta) | dim, separator(),
                         vbox(std::move(list)) | vscroll_indicator | yframe | flex }));
}

static Element build_gauges_pane(const Snapshot &snap, int width) {
    Elements g;
    for (std::size_t i = 0; i < 3; i++) {
        if (i < snap.top3.size()) {
            auto &e = snap.top3[i];
            std::string org = (e.origin == e.comm) ? std::string() : (" <" + e.origin + ">");
            std::string lbl = "[" + std::to_string(e.pid) + "] " + e.comm + org + " " + fmt_pct(e.risk_pct);
            Color c = risk_color(e.risk_pct);
            g.push_back(wrap_indent(lbl, width, 2, c, false));
            g.push_back(gauge(static_cast<float>(e.risk_pct)) | color(c));
        } else {
            g.push_back(text(" (idle) ") | dim);
            g.push_back(gauge(0.0f) | color(Color::GrayDark));
        }
    }
    return window(text(" Threat Gauges (own risk) ") | bold, vbox(std::move(g)));
}

static Element build_watchlist_pane(const Snapshot &snap, int width) {
    Elements w;
    if (snap.watchlist.empty()) {
        w.push_back(text(" (empty; flags at peak >= 40%) ") | dim);
    } else {
        std::size_t limit = std::min<std::size_t>(8, snap.watchlist.size());
        for (std::size_t i = 0; i < limit; i++) {
            auto &e = snap.watchlist[i];
            std::string org = (e.origin == e.comm) ? std::string("self") : e.origin;
            std::string head = e.first_tstr + (e.is_dead ? " x " : "   ")
                + "[" + std::to_string(e.pid) + "] ";
            std::string body = e.comm + " from:" + org
                + " pk=" + fmt_pct(e.peak_risk_pct)
                + " cur=" + fmt_pct(e.current_risk_pct)
                + " ch=" + std::to_string(e.child_count)
                + " st=" + (e.stages.empty() ? std::string("-") : e.stages);
            Color c = e.is_dead ? Color::GrayDark : risk_color(e.peak_risk_pct);
            int indent = (int)head.size();
            w.push_back(wrap_indent(head + body, width, indent, c, false));
        }
    }
    return window(text(" Watchlist [first | from:launcher | L/X/M/P/E/C] ") | bold,
                  vbox(std::move(w)) | vscroll_indicator | yframe);
}

static Element build_masq_pane(const Snapshot &snap, int width) {
    Elements m;
    if (snap.masq_events.empty()) {
        m.push_back(text(" (no renames observed) ") | dim);
    } else {
        for (auto &e : snap.masq_events) {
            std::string head = e.tstr + " [" + std::to_string(e.pid) + "] ";
            std::string body = "'" + e.old_comm + "' -> '" + e.new_comm + "'"
                + (e.suspicious ? " [!]" : "");
            Color c = e.suspicious ? Color::Magenta : Color::GrayLight;
            int indent = (int)head.size();
            m.push_back(wrap_indent(head + body, width, indent, c, e.suspicious));
        }
    }
    return window(text(" Rename / Masquerade Log ") | bold,
                  vbox(std::move(m)) | vscroll_indicator | yframe);
}

static Element build_audit_pane(const std::vector<std::string> &lines, int width, int roff) {
    Elements a;
    if (lines.empty()) {
        a.push_back(text(" (no alerts) ") | dim);
    } else {
        for (auto &s : lines) {
            Color c = Color::Yellow;
            if (s.find("[BURST]") != std::string::npos) c = Color::Red;
            else if (s.find("LSM-DENY") != std::string::npos) c = Color::Magenta;
            else if (s.find("[BLOCK]") != std::string::npos) c = Color::Magenta;
            else if (s.find("[LSM]") != std::string::npos) c = Color::Cyan;
            else if (s.find("KILL") != std::string::npos) c = Color::Red;
            else if (s.find("FREEZE") != std::string::npos) c = Color::Cyan;
            else if (s.find("RESUME") != std::string::npos) c = Color::Green;
            else if (s.find("WHITELIST") != std::string::npos) c = Color::Green;
            else if (s.find("MASQUERADE") != std::string::npos) c = Color::Magenta;
            else if (s.find("[hook]") != std::string::npos) c = Color::Cyan;
            int indent = 15;
            std::size_t rb = s.find(']');
            if (rb != std::string::npos && rb + 2 <= s.size()) indent = (int)rb + 2;
            a.push_back(wrap_indent(s, width, indent, c, false));
        }
    }
    char title[64];
    std::snprintf(title, sizeof(title), " Audit Log %s ", roff > 0 ? "(history)" : "(live)");
    return window(text(title) | bold, vbox(std::move(a)));
}

static Element build_modal(const PromptReq &p, int width) {
    std::string org = (p.origin == p.comm) ? std::string() : ("  (from: " + p.origin + ")");
    int inner = width - 6;
    if (inner < 20) inner = 20;
    Elements v;
    v.push_back(text("  THREAT FROZEN - AWAITING DECISION  ") | bold | color(Color::Black) | bgcolor(Color::Red) | center);
    v.push_back(text(""));
    v.push_back(wrap_indent("  Process : [" + std::to_string(p.pid) + "] " + p.comm + org,
                            inner, 12, Color::White, true));
    char l2[64];
    std::snprintf(l2, sizeof(l2), "  Risk    : %.1f%%", p.risk * 100.0);
    v.push_back(text(l2) | color(Color::Red) | bold);
    v.push_back(wrap_indent("  Flagged : it tried to " + p.doing, inner, 12, Color::Yellow, false));
    v.push_back(text("            (this action ran; process now suspended before the next)") | dim);
    v.push_back(text(""));
    v.push_back(separator());
    v.push_back(wrap_indent("  [Y] allow -> " + p.allow_lbl, inner, 14, Color::Green, false));
    v.push_back(wrap_indent("  [N] deny  -> " + p.deny_lbl, inner, 14, Color::Yellow, false));
    v.push_back(text("  [B] block -> resume; deny risky syscalls in-kernel (LSM)") | color(Color::Magenta));
    v.push_back(wrap_indent("  [K] kill  -> " + p.kill_lbl, inner, 14, Color::Red, false));
    v.push_back(wrap_indent("  [W] w-list-> " + p.wl_lbl, inner, 14, Color::Cyan, false));
    v.push_back(text("  [Esc] dismiss (leave suspended, no action) ") | dim);
    return window(text(" THREAT CONFIRMATION ") | bold | color(Color::Red),
                  vbox(std::move(v)))
           | size(WIDTH, EQUAL, width) | bgcolor(Color::Black) | clear_under;
}

void Ui::run() {
    auto screen = ScreenInteractive::Fullscreen();
    int sel = 0;
    bool new_only = false;
    bool paused = false;
    bool modal_up = false;
    PromptReq active;
    int roff = 0, hoff_l = 0;
    const int VIS_AUDIT = 10;
    const int RIGHT_W = 62;

    Snapshot fsnap;
    std::vector<std::string> falerts;
    std::uint64_t prev_ev = 0;
    double prev_t = 0.0, ema_rate = 0.0;

    auto renderer = Renderer([&]() {
        if (!modal_up && tr_->prompts_enabled()) {
            auto p = tr_->take_prompt();
            if (p) { active = *p; modal_up = true; }
        }

        Snapshot snap = (paused && !modal_up) ? fsnap : tr_->snapshot();
        std::vector<std::string> all = (paused && !modal_up) ? falerts : tr_->tail_alerts(999);

        {
            using namespace std::chrono;
            double nowt = duration<double>(steady_clock::now().time_since_epoch()).count();
            std::uint64_t ev = tr_->ev_count();
            if (prev_t > 0.0 && nowt > prev_t) {
                double inst = (double)(ev - prev_ev) / (nowt - prev_t);
                ema_rate = ema_rate * 0.7 + inst * 0.3;
            }
            prev_ev = ev; prev_t = nowt;
        }

        int total = (int)all.size();
        int maxroff = std::max(0, total - VIS_AUDIT);
        if (roff > maxroff) roff = maxroff;
        if (roff < 0) roff = 0;
        int endi = total - roff;
        int starti = std::max(0, endi - VIS_AUDIT);
        std::vector<std::string> awin(all.begin() + starti, all.begin() + endi);

        double wr = tr_->warmup_remaining();
        char armed[32];
        if (wr > 0.0) std::snprintf(armed, sizeof(armed), "WARMUP %.0fs", wr);
        else          std::snprintf(armed, sizeof(armed), "ARMED");

        char status[380];
        std::snprintf(status, sizeof(status),
            " EDR | ev=%llu %.0f/s | kills=%llu burst=%llu dny=%llu hookfail=%llu | watch=%zu frozen=%zu blk=%zu | ENF:%s | %s | %s%s | e:enf X:clr space q ",
            (unsigned long long)tr_->ev_count(), ema_rate,
            (unsigned long long)tr_->kills_issued(),
            (unsigned long long)tr_->burst_trips(),
            (unsigned long long)tr_->denies(),
            (unsigned long long)tr_->hooks_failed(),
            snap.watch_count, snap.frozen_count, tr_->blocks_active(),
            tr_->enforcement_on() ? "on" : "OFF",
            armed, new_only ? "NEW" : "ALL",
            paused ? " [PAUSED]" : "");
        Color barcol = modal_up ? Color::Red : (paused ? Color::Magenta : Color::Blue);

        int rw_inner = RIGHT_W - 4;
        auto right = vbox({
            build_gauges_pane(snap, rw_inner)     | size(HEIGHT, EQUAL, 9),
            build_watchlist_pane(snap, rw_inner)  | size(HEIGHT, EQUAL, 13),
            build_masq_pane(snap, rw_inner)       | size(HEIGHT, EQUAL, 11),
            build_audit_pane(awin, rw_inner, roff) | flex
        });
        Element bview = vbox({
            wrap_indent(status, screen.dimx(), 0, Color::White, true) | bgcolor(barcol),
            hbox({ build_tree_pane(snap, sel, new_only, hoff_l) | flex_grow,
                   right | size(WIDTH, EQUAL, RIGHT_W) }) | flex
        });
        if (modal_up) {
            int mw = std::min(78, screen.dimx() - 4);
            return dbox({ bview | dim, build_modal(active, mw) | center });
        }
        return bview;
    });

    auto with_keys = CatchEvent(renderer, [&](Event e) {
        if (modal_up) {
            if (e == Event::Character('y') || e == Event::Character('Y')) {
                tr_->resolve_prompt(active.uid, active.pgid, 'y'); modal_up = false; return true;
            }
            if (e == Event::Character('n') || e == Event::Character('N')) {
                tr_->resolve_prompt(active.uid, active.pgid, 'n'); modal_up = false; return true;
            }
            if (e == Event::Character('b') || e == Event::Character('B')) {
                tr_->resolve_prompt(active.uid, active.pgid, 'b'); modal_up = false; return true;
            }
            if (e == Event::Character('k') || e == Event::Character('K')) {
                tr_->resolve_prompt(active.uid, active.pgid, 'k'); modal_up = false; return true;
            }
            if (e == Event::Character('w') || e == Event::Character('W')) {
                tr_->resolve_prompt(active.uid, active.pgid, 'w'); modal_up = false; return true;
            }
            if (e == Event::Escape) {
                tr_->resolve_prompt(active.uid, active.pgid, 'x'); modal_up = false; return true;
            }
            return true;
        }

        Snapshot snap = paused ? fsnap : tr_->snapshot();
        auto rows = build_flat(snap, new_only);
        int max_sel = std::max(0, (int)rows.size() - 1);

        if (e == Event::Character('q') || e == Event::Character('Q')) {
            stop_.store(true); tr_->stop(); screen.ExitLoopClosure()(); return true;
        }
        if (e == Event::Character(' ')) {
            paused = !paused;
            if (paused) { fsnap = tr_->snapshot(); falerts = tr_->tail_alerts(999); }
            return true;
        }
        if (e == Event::ArrowUp   || e == Event::Character('k')) { sel = std::max(0, sel - 1); return true; }
        if (e == Event::ArrowDown || e == Event::Character('j')) { sel = std::min(max_sel, sel + 1); return true; }
        if (e == Event::PageUp)   { sel = std::max(0, sel - 10); return true; }
        if (e == Event::PageDown) { sel = std::min(max_sel, sel + 10); return true; }
        if (e == Event::Character('g')) { sel = 0; return true; }
        if (e == Event::Character('G')) { sel = max_sel; return true; }
        if (e == Event::Character('n')) { new_only = true; sel = 0; return true; }
        if (e == Event::Character('a')) { new_only = false; sel = 0; return true; }
        if (e == Event::Character('0')) { hoff_l = 0; return true; }
        if (e == Event::Character('e')) { tr_->set_enforcement(!tr_->enforcement_on()); return true; }
        if (e == Event::Character('X')) { tr_->flush_blocks(); return true; }

        if (e.is_mouse()) {
            auto m = e.mouse();
            if (m.button != Mouse::WheelUp && m.button != Mouse::WheelDown) return false;
            bool up = (m.button == Mouse::WheelUp);
            int split = screen.dimx() - RIGHT_W;
            bool over_right = (m.x >= split);
            if (over_right) {
                roff = up ? std::max(0, roff - 2) : roff + 2;
            } else {
                if (m.shift) hoff_l = up ? std::max(0, hoff_l - 4) : hoff_l + 4;
                else         sel    = up ? std::max(0, sel - 1)    : std::min(max_sel, sel + 1);
            }
            return true;
        }
        return false;
    });

    std::thread refresh([&]() {
        while (!stop_.load() && tr_->running()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
            screen.PostEvent(Event::Custom);
        }
    });
    screen.Loop(with_keys);
    stop_.store(true);
    if (refresh.joinable()) refresh.join();
}