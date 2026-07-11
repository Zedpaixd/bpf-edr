#include "ui.h"
#include "ui_common.h"
#include "reputation.h"
#include "keymap.h"
#include <ftxui/component/event.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/color.hpp>
#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

using namespace ftxui;

static std::vector<RepEntry> g_repview;

struct KBRow { const char *label; KmAction action; const char *desc; bool header; };

static std::vector<KBRow> keybind_rows() {
    return {
        { "DASHBOARD", KM_COUNT, "", true },
        { nullptr, KM_SEL_DOWN, "move selection down", false },
        { nullptr, KM_SEL_UP, "move selection up", false },
        { nullptr, KM_SEL_TOP, "jump to top", false },
        { nullptr, KM_SEL_BOTTOM, "jump to bottom", false },
        { nullptr, KM_NEWONLY, "show new processes only", false },
        { nullptr, KM_ALL, "show all processes", false },
        { nullptr, KM_PAUSE, "pause / resume view", false },
        { nullptr, KM_ENFORCE, "toggle kernel enforcement", false },
        { nullptr, KM_CLEAR, "clear all active blocks", false },
        { nullptr, KM_LAUNCH, "launch a supervised process", false },
        { nullptr, KM_REPMAN, "open reputation manager", false },
        { nullptr, KM_KEYPANE, "toggle this help", false },
        { nullptr, KM_RESET_H, "reset horizontal scroll", false },
        { nullptr, KM_QUIT, "quit", false },
        { "eBPF DECISION MODAL", KM_COUNT, "", true },
        { nullptr, KM_ALLOW, "allow (resume)", false },
        { nullptr, KM_DENY, "deny (keep suspended)", false },
        { nullptr, KM_BLOCK, "block risky syscalls (kernel)", false },
        { nullptr, KM_KILL, "kill process group", false },
        { nullptr, KM_BLACKLIST, "blacklist binary (hash)", false },
        { nullptr, KM_WHITELIST, "whitelist binary (hash)", false },
        { nullptr, KM_SESSION_WL, "session-only allow", false },
        { "SUPERVISED (seccomp) MODAL", KM_COUNT, "", true },
        { nullptr, KM_ALLOW, "allow this syscall", false },
        { nullptr, KM_DENY, "deny this syscall (EPERM)", false },
        { nullptr, KM_KILL, "deny and kill", false },
        { nullptr, KM_BLACKLIST, "blacklist binary (hash)", false },
        { nullptr, KM_WHITELIST, "whitelist binary (hash)", false },
        { "REPUTATION MANAGER", KM_COUNT, "", true },
        { nullptr, KM_REP_PAUSE, "pause / resume a rule", false },
        { nullptr, KM_REP_REMOVE, "remove a rule", false },
        { "Esc always cancels / closes.", KM_COUNT, "", true },
    };
}

static Element render_kb_rows(const Keymap &km, int from, int count) {
    auto rows = keybind_rows();
    Elements v;
    int shown = 0;
    for (int i = from; i < (int)rows.size() && (count < 0 || shown < count); i++) {
        auto &r = rows[i];
        if (r.header) {
            v.push_back(text(std::string(" ") + r.label) | bold | color(Color::Cyan));
        } else {
            std::string key = km.key_for(r.action);
            if (key == " ") key = "spc";
            std::string line = " [" + key + "]";
            while (line.size() < 8) line += ' ';
            line += r.desc;
            v.push_back(text(line) | color(Color::GrayLight));
        }
        shown++;
    }
    return vbox(std::move(v));
}

ftxui::Element build_keybind_pane(const Keymap &km) {
    return window(text(" Keybinds (?) ") | bold,
                  render_kb_rows(km, 0, -1) | vscroll_indicator | yframe);
}

ftxui::Element build_keybind_modal(const Keymap &km, int width, int height, int scroll) {
    auto rows = keybind_rows();
    int maxscroll = std::max(0, (int)rows.size() - (height - 4));
    if (scroll > maxscroll) scroll = maxscroll;
    if (scroll < 0) scroll = 0;
    return window(text(" Keybinds — scroll j/k or arrows, Esc closes ") | bold | color(Color::Cyan),
                  render_kb_rows(km, scroll, height - 4))
           | size(WIDTH, EQUAL, width) | size(HEIGHT, EQUAL, height)
           | bgcolor(Color::Black) | clear_under;
}

ftxui::Element build_repman_view(const std::shared_ptr<Tracker> &tr,
                                 int width, int &sel, bool &dirty) {
    auto rep = tr->reputation();
    if (dirty) {
        g_repview = rep ? rep->list() : std::vector<RepEntry>();
        dirty = false;
    }
    int inner = width - 4;
    if (inner < 40) inner = 40;

    Elements rows;
    if (g_repview.empty()) {
        rows.push_back(text(" (no saved binaries yet — blacklist or whitelist one from a decision modal) ")
                       | dim | center);
    } else {
        if (sel < 0) sel = 0;
        if (sel >= (int)g_repview.size()) sel = (int)g_repview.size() - 1;
        for (int i = 0; i < (int)g_repview.size(); i++) {
            auto &e = g_repview[i];
            const char *kind = (e.kind == REP_BLACKLIST) ? "BLOCK" : "TRUST";
            const char *st = e.paused ? "PAUSED" : "active";
            std::string head = std::string(" ") + kind + " " + st + "  ";
            std::string body = (e.name.empty() ? std::string("?") : e.name)
                + "  " + uic::short_hash(e.hash)
                + "  " + (e.path.empty() ? std::string("<path?>") : e.path)
                + "  (added " + e.added_tstr + ")";
            Color c;
            if (e.paused) c = Color::GrayDark;
            else if (e.kind == REP_BLACKLIST) c = Color::Red;
            else c = Color::Green;
            int indent = (int)head.size();
            Element row = uic::wrap_indent(head + body, inner, indent, c, (i == sel));
            if (i == sel) row = row | inverted;
            rows.push_back(row);
        }
    }

    char meta[176];
    std::snprintf(meta, sizeof(meta),
        " saved binaries=%zu | sel %d/%zu | [p] pause/resume  [x] remove  [Esc] close ",
        g_repview.size(), g_repview.empty() ? 0 : sel + 1, g_repview.size());

    Element tamper = rep && rep->tamper_flagged()
        ? (text(" ! reputation store checksum MISMATCH — possible tampering ! ")
           | bold | color(Color::Black) | bgcolor(Color::Red))
        : (text("") | dim);

    return window(text(" Reputation Manager — saved binary verdicts ") | bold | color(Color::Cyan),
                  vbox({ tamper, text(meta) | dim, separator(),
                         vbox(std::move(rows)) | vscroll_indicator | yframe | flex }))
           | size(WIDTH, EQUAL, width) | bgcolor(Color::Black) | clear_under;
}

bool repman_handle_key(const std::shared_ptr<Tracker> &tr,
                       const ftxui::Event &e, const Keymap &km,
                       int &sel, bool &close_req) {
    close_req = false;
    int n = (int)g_repview.size();
    if (e == Event::Escape || km.matches(e, KM_REPMAN)) { close_req = true; return true; }
    if (e == Event::ArrowDown || km.matches(e, KM_SEL_DOWN)) { if (n > 0) sel = std::min(n - 1, sel + 1); return true; }
    if (e == Event::ArrowUp || km.matches(e, KM_SEL_UP)) { if (n > 0) sel = std::max(0, sel - 1); return true; }
    if (km.matches(e, KM_SEL_TOP)) { sel = 0; return true; }
    if (km.matches(e, KM_SEL_BOTTOM)) { sel = std::max(0, n - 1); return true; }
    if (n == 0) return true;
    auto rep = tr->reputation();
    if (!rep || sel < 0 || sel >= n) return true;
    RepEntry cur = g_repview[sel];
    if (km.matches(e, KM_REP_PAUSE)) {
        rep->set_paused(cur.hash, cur.kind, !cur.paused);
        if (cur.kind == REP_BLACKLIST) {
            if (!cur.paused) tr->unblock_hash_live(cur.hash);
            else             tr->reblock_from_reputation(cur.hash);
        }
        g_repview = rep->list();
        return true;
    }
    if (km.matches(e, KM_REP_REMOVE)) {
        rep->remove(cur.hash, cur.kind);
        if (cur.kind == REP_BLACKLIST) tr->unblock_hash_live(cur.hash);
        g_repview = rep->list();
        if (sel >= (int)g_repview.size()) sel = std::max(0, (int)g_repview.size() - 1);
        return true;
    }
    return true;
}