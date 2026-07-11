#include "keymap.h"
#include "json.hpp"
#include <fstream>
#include <sstream>

using nlohmann::json;
using namespace ftxui;

static const char *km_name(KmAction a) {
    switch (a) {
        case KM_QUIT: return "quit";
        case KM_REPMAN: return "reputation_manager";
        case KM_KEYPANE: return "keybind_pane";
        case KM_LAUNCH: return "launch_supervised";
        case KM_PAUSE: return "pause_dashboard";
        case KM_ENFORCE: return "toggle_enforcement";
        case KM_CLEAR: return "clear_blocks";
        case KM_NEWONLY: return "filter_new_only";
        case KM_ALL: return "filter_all";
        case KM_RESET_H: return "reset_hscroll";
        case KM_SEL_UP: return "sel_up";
        case KM_SEL_DOWN: return "sel_down";
        case KM_SEL_TOP: return "sel_top";
        case KM_SEL_BOTTOM: return "sel_bottom";
        case KM_ALLOW: return "modal_allow";
        case KM_DENY: return "modal_deny";
        case KM_BLOCK: return "modal_block";
        case KM_BLACKLIST: return "modal_blacklist";
        case KM_WHITELIST: return "modal_whitelist";
        case KM_KILL: return "modal_kill";
        case KM_SESSION_WL: return "modal_session_wl";
        case KM_REP_PAUSE: return "repman_pause";
        case KM_REP_REMOVE: return "repman_remove";
        case KM_SUP_VIEW: return "supervised_view";
        case KM_SUP_INPUT: return "supervised_input";
        case KM_SUP_SKIP: return "supervised_skip_unscored";
        default: return "";
    }
}

Keymap::Keymap() { set_defaults(); }

void Keymap::set_defaults() {
    keys_[KM_QUIT] = "q";
    keys_[KM_REPMAN] = "R";
    keys_[KM_KEYPANE] = "?";
    keys_[KM_LAUNCH] = "S";
    keys_[KM_PAUSE] = " ";
    keys_[KM_ENFORCE] = "e";
    keys_[KM_CLEAR] = "X";
    keys_[KM_NEWONLY] = "n";
    keys_[KM_ALL] = "a";
    keys_[KM_RESET_H] = "0";
    keys_[KM_SEL_UP] = "k";
    keys_[KM_SEL_DOWN] = "j";
    keys_[KM_SEL_TOP] = "g";
    keys_[KM_SEL_BOTTOM] = "G";
    keys_[KM_ALLOW] = "y";
    keys_[KM_DENY] = "n";
    keys_[KM_BLOCK] = "b";
    keys_[KM_BLACKLIST] = "d";
    keys_[KM_WHITELIST] = "l";
    keys_[KM_KILL] = "k";
    keys_[KM_SESSION_WL] = "w";
    keys_[KM_REP_PAUSE] = "p";
    keys_[KM_REP_REMOVE] = "x";
    keys_[KM_SUP_VIEW] = "o";
    keys_[KM_SUP_INPUT] = "i";
    keys_[KM_SUP_SKIP] = "u";
}

void Keymap::load(const std::string &path, std::string &note) {
    note.clear();
    std::ifstream ifs(path);
    if (!ifs.is_open()) { note = "binds.json not found; using defaults"; return; }
    std::stringstream buf; buf << ifs.rdbuf();
    json j = json::parse(buf.str(), nullptr, false, true);
    if (j.is_discarded()) { note = "binds.json malformed; using defaults"; return; }
    int applied = 0;
    for (int a = 0; a < KM_COUNT; a++) {
        const char *nm = km_name((KmAction)a);
        if (j.contains(nm) && j[nm].is_string()) {
            std::string v = j[nm].get<std::string>();
            if (!v.empty()) { keys_[a] = v; applied++; }
        }
    }
    note = "binds.json loaded (" + std::to_string(applied) + " bindings)";
}

std::string Keymap::key_for(KmAction a) const {
    if (a < 0 || a >= KM_COUNT) return "";
    return keys_[a];
}

bool Keymap::matches(const Event &e, KmAction a) const {
    if (a < 0 || a >= KM_COUNT) return false;
    const std::string &k = keys_[a];
    if (k.empty()) return false;
    if (k == " ") return e == Event::Character(' ');
    if (k == "esc") return e == Event::Escape;
    if (k == "up") return e == Event::ArrowUp;
    if (k == "down") return e == Event::ArrowDown;
    if (k == "pgup") return e == Event::PageUp;
    if (k == "pgdn") return e == Event::PageDown;
    if (k.size() == 1) return e == Event::Character(k);
    return false;
}