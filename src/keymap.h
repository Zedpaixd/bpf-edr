#ifndef EDR_KEYMAP_H
#define EDR_KEYMAP_H

#include <ftxui/component/event.hpp>
#include <string>

enum KmAction {
    KM_QUIT, KM_REPMAN, KM_KEYPANE, KM_LAUNCH, KM_PAUSE, KM_ENFORCE, KM_CLEAR,
    KM_NEWONLY, KM_ALL, KM_RESET_H, KM_SEL_UP, KM_SEL_DOWN, KM_SEL_TOP, KM_SEL_BOTTOM,
    KM_ALLOW, KM_DENY, KM_BLOCK, KM_BLACKLIST, KM_WHITELIST, KM_KILL, KM_SESSION_WL,
    KM_REP_PAUSE, KM_REP_REMOVE, KM_SUP_VIEW, KM_SUP_INPUT, KM_SUP_SKIP, KM_PURGE,
    KM_COUNT
};

class Keymap {
public:
    Keymap();
    void load(const std::string &path, std::string &note);
    bool matches(const ftxui::Event &e, KmAction a) const;
    std::string key_for(KmAction a) const;

private:
    void set_defaults();
    std::string keys_[KM_COUNT];
};

#endif