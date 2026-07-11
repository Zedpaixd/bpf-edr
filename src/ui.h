#ifndef EDR_UI_H
#define EDR_UI_H

#include "tracker.h"
#include "keymap.h"
#include "seccomp_supervisor.h"
#include <ftxui/dom/elements.hpp>
#include <ftxui/component/event.hpp>
#include <atomic>
#include <memory>
#include <thread>

ftxui::Element build_repman_view(const std::shared_ptr<Tracker> &tr,
                                 int width, int &sel, bool &dirty);
bool repman_handle_key(const std::shared_ptr<Tracker> &tr,
                       const ftxui::Event &e, const Keymap &km,
                       int &sel, bool &close_req);
ftxui::Element build_keybind_pane(const Keymap &km);
ftxui::Element build_keybind_modal(const Keymap &km, int width, int height, int scroll);

class Ui {
public:
    Ui(std::shared_ptr<Tracker> t, std::shared_ptr<SeccompSupervisor> sup, Keymap km);
    void run();
    void stop();
private:
    std::shared_ptr<Tracker> tr_;
    std::shared_ptr<SeccompSupervisor> sup_;
    Keymap km_;
    std::atomic<bool> stop_{false};
};

#endif