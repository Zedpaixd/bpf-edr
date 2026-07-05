#include "ui.h"
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/color.hpp>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>

using namespace ftxui;

Ui::Ui(std::shared_ptr<Tracker> t) : tr_(std::move(t)) {}
void Ui::stop() { stop_.store(true); }

static Color pick_color(double r) {
    if (r < 0.20) return Color::Green;
    if (r < 0.75) return Color::Yellow;
    return Color::Red;
}

static std::string fmt_pct(double r) {
    char b[16];
    std::snprintf(b, sizeof(b), "%5.1f%%", r * 100.0);
    return b;
}

static Element render_node(const SnapNode &n, int depth) {
    std::string indent(depth * 2, ' ');
    std::string label = indent + "[" + std::to_string(n.pid) + "] " + n.comm
                        + " - " + fmt_pct(n.risk_pct)
                        + (n.is_dead ? " (dead)" : "");
    Element self = text(label) | color(n.is_dead ? Color::GrayDark : pick_color(n.risk_pct));
    Elements out;
    out.push_back(self);
    for (auto &c : n.children) out.push_back(render_node(c, depth + 1));
    return vbox(std::move(out));
}

static Element render_tree_pane(const Snapshot &s) {
    Elements v;
    if (s.roots.empty()) {
        v.push_back(text(" (no processes tracked yet) ") | dim);
    } else {
        for (auto &r : s.roots) v.push_back(render_node(r, 0));
    }
    char meta[96];
    std::snprintf(meta, sizeof(meta), " tracked: live=%zu total=%zu ",
        s.live_nodes, s.total_nodes);
    return window(text(" Lineage & State ") | bold,
                  vbox({ text(meta) | dim, separator(), vbox(std::move(v)) | vscroll_indicator | yframe }));
}

static Element render_gauges(const Snapshot &s) {
    Elements rows;
    for (std::size_t i = 0; i < 3; i++) {
        if (i < s.top3.size()) {
            auto &e = s.top3[i];
            std::string lbl = "[" + std::to_string(e.pid) + "] " + e.comm + " " + fmt_pct(e.risk_pct);
            Color c = pick_color(e.risk_pct);
            rows.push_back(vbox({
                text(lbl) | color(c),
                gauge(static_cast<float>(e.risk_pct)) | color(c) | flex,
                separator()
            }));
        } else {
            rows.push_back(vbox({
                text(" (idle) ") | dim,
                gauge(0.0f) | color(Color::GrayDark),
                separator()
            }));
        }
    }
    return window(text(" Threat Gauges ") | bold, vbox(std::move(rows)));
}

static Element render_alerts(const std::vector<std::string> &al) {
    Elements v;
    if (al.empty()) {
        v.push_back(text(" (no alerts) ") | dim);
    } else {
        for (auto &s : al) {
            Color c = Color::White;
            if (s.rfind("[KILL]", 0) == 0) c = Color::Red;
            else if (s.find("MASQUERADE") != std::string::npos) c = Color::Magenta;
            else if (s.find("commit_creds") != std::string::npos) c = Color::RedLight;
            else c = Color::Yellow;
            v.push_back(text(s) | color(c));
        }
    }
    return window(text(" Security Audit Log ") | bold,
                  vbox(std::move(v)) | vscroll_indicator | yframe);
}

void Ui::run() {
    auto screen = ScreenInteractive::Fullscreen();
    auto renderer = Renderer([&]() {
        auto snap = tr_->snapshot();
        auto al = tr_->tail_alerts(15);
        char status[160];
        std::snprintf(status, sizeof(status),
            " EDR | events=%llu kills=%llu hook_fail=%llu | q: quit ",
            (unsigned long long)tr_->ev_count(),
            (unsigned long long)tr_->kills_issued(),
            (unsigned long long)tr_->hooks_failed());
        auto left = render_tree_pane(snap);
        auto right = vbox({
            render_gauges(snap),
            render_alerts(al) | flex
        });
        return vbox({
            text(status) | bold | bgcolor(Color::Blue),
            hbox({
                left | flex_grow,
                right | size(WIDTH, EQUAL, 60)
            }) | flex
        });
    });
    auto ev_handler = CatchEvent(renderer, [&](Event e) {
        if (e == Event::Character('q') || e == Event::Character('Q')) {
            stop_.store(true);
            tr_->stop();
            screen.ExitLoopClosure()();
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
    screen.Loop(ev_handler);
    stop_.store(true);
    if (refresh.joinable()) refresh.join();
}