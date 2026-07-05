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
    bool is_dead;
    bool is_new;
    bool is_anchor;
    bool exempt;
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

static void collapse_walk(const SnapNode &n, int depth, bool parent_exempt,
                          bool anchor_used, std::vector<FlatRow> &out) {
    if (!n.exempt) {
        out.push_back({depth, n.pid, n.comm, n.risk_pct, n.is_dead, n.is_new, false, false});
        for (auto &c : n.children) collapse_walk(c, depth + 1, false, anchor_used, out);
    } else {
        bool anchor = (!anchor_used && !parent_exempt);
        if (anchor) {
            out.push_back({depth, n.pid, n.comm, n.risk_pct, n.is_dead, n.is_new, true, true});
            for (auto &c : n.children) collapse_walk(c, depth + 1, true, true, out);
        } else {
            for (auto &c : n.children) collapse_walk(c, depth, true, anchor_used, out);
        }
    }
}

static void newonly_walk(const SnapNode &n, std::vector<FlatRow> &out) {
    if (n.is_new && !n.exempt)
        out.push_back({0, n.pid, n.comm, n.risk_pct, n.is_dead, true, false, false});
    for (auto &c : n.children) newonly_walk(c, out);
}

static std::vector<FlatRow> build_flat(const Snapshot &snap, bool new_only) {
    std::vector<FlatRow> rows;
    if (new_only) {
        for (auto &r : snap.roots) newonly_walk(r, rows);
    } else {
        for (auto &r : snap.roots) collapse_walk(r, 0, false, false, rows);
    }
    return rows;
}

static Element make_row(const FlatRow &r, bool selected, int hoff) {
    std::string prefix(r.depth * 2, ' ');
    prefix += r.is_new ? "* " : "  ";
    std::string label = prefix + "[" + std::to_string(r.pid) + "] " + r.comm
                        + " - " + fmt_pct(r.risk_pct)
                        + (r.is_dead ? " (dead)" : "")
                        + (r.is_anchor ? "  <shell>" : "");
    Color c;
    if (r.is_dead)        c = Color::GrayDark;
    else if (r.is_anchor) c = Color::GrayDark;
    else if (r.exempt)    c = Color::GrayLight;
    else                  c = risk_color(r.risk_pct);
    Element el = text(hclip(label, hoff)) | color(c);
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
    for (int i = 0; i < (int)rows.size(); i++)
        list.push_back(make_row(rows[i], i == sel, hoff));
    char meta[208];
    std::snprintf(meta, sizeof(meta),
        " %s | row %d/%zu | live=%zu new=%zu total=%zu | H%+d ",
        new_only ? "NEW ONLY (a: all)" : "ALL (n: new only)",
        sel + 1, rows.size(), snap.live_nodes, snap.new_nodes, snap.total_nodes, hoff);
    return window(text(" Lineage & State ") | bold,
                  vbox({
                      text(meta) | dim,
                      separator(),
                      vbox(std::move(list)) | vscroll_indicator | yframe | flex
                  }));
}

static Element build_gauges_pane(const Snapshot &snap, int hoff) {
    Elements g;
    for (std::size_t i = 0; i < 3; i++) {
        if (i < snap.top3.size()) {
            auto &e = snap.top3[i];
            std::string lbl = "[" + std::to_string(e.pid) + "] " + e.comm + " " + fmt_pct(e.risk_pct);
            Color c = risk_color(e.risk_pct);
            g.push_back(text(hclip(lbl, hoff)) | color(c));
            g.push_back(gauge(static_cast<float>(e.risk_pct)) | color(c));
        } else {
            g.push_back(text(" (idle) ") | dim);
            g.push_back(gauge(0.0f) | color(Color::GrayDark));
        }
    }
    return window(text(" Threat Gauges ") | bold, vbox(std::move(g)));
}

static Element build_watchlist_pane(const Snapshot &snap, int hoff) {
    Elements w;
    if (snap.watchlist.empty()) {
        w.push_back(text(" (empty; flags at peak >= 40%) ") | dim);
    } else {
        std::size_t limit = std::min<std::size_t>(8, snap.watchlist.size());
        for (std::size_t i = 0; i < limit; i++) {
            auto &e = snap.watchlist[i];
            std::string org = (e.origin == e.comm) ? std::string("self") : e.origin;
            char line[256];
            std::snprintf(line, sizeof(line),
                " %s %s [%u] %-11s from:%-11s pk=%s cur=%s ch=%zu st=%s",
                e.first_tstr.c_str(),
                e.is_dead ? "x" : " ",
                e.pid,
                e.comm.substr(0, 11).c_str(),
                org.substr(0, 11).c_str(),
                fmt_pct(e.peak_risk_pct).c_str(),
                fmt_pct(e.current_risk_pct).c_str(),
                e.child_count,
                e.stages.empty() ? "-" : e.stages.c_str());
            Color c = e.is_dead ? Color::GrayDark : risk_color(e.peak_risk_pct);
            w.push_back(text(hclip(line, hoff)) | color(c));
        }
    }
    return window(text(" Watchlist [first | from:origin | L/X/M/P/E/C] ") | bold,
                  vbox(std::move(w)) | vscroll_indicator | yframe);
}

static Element build_masq_pane(const Snapshot &snap, int hoff) {
    Elements m;
    if (snap.masq_events.empty()) {
        m.push_back(text(" (no renames observed) ") | dim);
    } else {
        for (auto &e : snap.masq_events) {
            std::string line = " " + e.tstr + " [" + std::to_string(e.pid) + "] '"
                + e.old_comm + "' -> '" + e.new_comm + "'"
                + (e.suspicious ? " [!]" : "");
            Element el = text(hclip(line, hoff));
            el = e.suspicious ? (el | color(Color::Magenta) | bold)
                              : (el | color(Color::GrayLight) | dim);
            m.push_back(el);
        }
    }
    return window(text(" Rename / Masquerade Log ") | bold,
                  vbox(std::move(m)) | vscroll_indicator | yframe);
}

static Element build_audit_pane(const std::vector<std::string> &lines, int hoff, int roff) {
    Elements a;
    if (lines.empty()) {
        a.push_back(text(" (no alerts) ") | dim);
    } else {
        for (auto &s : lines) {
            Color c = Color::Yellow;
            if (s.find("[WOULD-KILL]") != std::string::npos) c = Color::Red;
            else if (s.find("[KILL]") != std::string::npos) c = Color::Red;
            else if (s.find("MASQUERADE") != std::string::npos) c = Color::Magenta;
            else if (s.find("[hook]") != std::string::npos) c = Color::Cyan;
            a.push_back(text(hclip(s, hoff)) | color(c));
        }
    }
    char title[64];
    std::snprintf(title, sizeof(title), " Audit Log %s ", roff > 0 ? "(scrolled back)" : "(live)");
    return window(text(title) | bold, vbox(std::move(a)));
}

void Ui::run() {
    auto screen = ScreenInteractive::Fullscreen();
    int sel = 0;
    bool new_only = false;
    int roff = 0;
    int hoff_l = 0;
    int hoff_r = 0;
    const int VIS_AUDIT = 10;

    auto renderer = Renderer([&]() {
        auto snap = tr_->snapshot();
        auto all = tr_->tail_alerts(999);
        int total = (int)all.size();
        int maxroff = std::max(0, total - VIS_AUDIT);
        if (roff > maxroff) roff = maxroff;
        if (roff < 0) roff = 0;
        int end = total - roff;
        int start = std::max(0, end - VIS_AUDIT);
        std::vector<std::string> awin(all.begin() + start, all.begin() + end);

        char status[256];
        std::snprintf(status, sizeof(status),
            " EDR | events=%llu wk=%llu hookfail=%llu | %s | wheel:scroll shift+wheel:H | 0:resetH n/a q ",
            (unsigned long long)tr_->ev_count(),
            (unsigned long long)tr_->kills_issued(),
            (unsigned long long)tr_->hooks_failed(),
            new_only ? "NEW-ONLY" : "ALL");

        auto right = vbox({
            build_gauges_pane(snap, hoff_r)          | size(HEIGHT, EQUAL, 9),
            build_watchlist_pane(snap, hoff_r)       | size(HEIGHT, EQUAL, 11),
            build_masq_pane(snap, hoff_r)            | size(HEIGHT, EQUAL, 11),
            build_audit_pane(awin, hoff_r, roff)     | flex
        });

        return vbox({
            text(status) | bold | bgcolor(Color::Blue),
            hbox({
                build_tree_pane(snap, sel, new_only, hoff_l) | flex_grow,
                right | size(WIDTH, EQUAL, 60)
            }) | flex
        });
    });

    auto with_keys = CatchEvent(renderer, [&](Event e) {
        auto snap = tr_->snapshot();
        auto rows = build_flat(snap, new_only);
        int max_sel = std::max(0, (int)rows.size() - 1);

        if (e == Event::Character('q') || e == Event::Character('Q')) {
            stop_.store(true);
            tr_->stop();
            screen.ExitLoopClosure()();
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
        if (e == Event::Character('0')) { hoff_l = 0; hoff_r = 0; return true; }

        if (e.is_mouse()) {
            auto m = e.mouse();
            if (m.button != Mouse::WheelUp && m.button != Mouse::WheelDown) return false;
            bool up = (m.button == Mouse::WheelUp);
            int split = screen.dimx() - 60;
            bool over_right = (m.x >= split);
            if (over_right) {
                if (m.shift) hoff_r = up ? std::max(0, hoff_r - 4) : hoff_r + 4;
                else         roff   = up ? std::max(0, roff - 2)   : roff + 2;
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
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            screen.PostEvent(Event::Custom);
        }
    });
    screen.Loop(with_keys);
    stop_.store(true);
    if (refresh.joinable()) refresh.join();
}