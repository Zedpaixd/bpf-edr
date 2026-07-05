#ifndef EDR_UI_H
#define EDR_UI_H

#include "tracker.h"
#include <atomic>
#include <memory>
#include <thread>

class Ui {
public:
    Ui(std::shared_ptr<Tracker> t);
    void run();
    void stop();
private:
    std::shared_ptr<Tracker> tr_;
    std::atomic<bool> stop_{false};
};

#endif