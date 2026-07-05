#ifndef EDR_MATH_ENGINE_H
#define EDR_MATH_ENGINE_H

#include <string>
#include <unordered_map>
#include <optional>
#include <cstdint>

struct EngineCfg {
    double lambda = 0.05;
    double k = 0.10;
    double x_0 = 50.0;
    double kill_threshold = 0.92;
    double backprop_factor = 0.25;
    int    backprop_max_depth = 3;
    double raw_score_cap = 500.0;
    int    tick_ms = 250;
    double gc_dead_ttl_sec = 30.0;
    double gc_tomb_risk_floor = 0.10;
    std::unordered_map<std::string, double> ev_w;
    double ctx_uid0 = 1.5;
    double ctx_ns = 1.3;
    double ctx_short = 1.2;
};

class MathEng {
public:
    static std::optional<EngineCfg> load(const std::string &path);
    static double sigmoid_stable(double x);
    static double apply_decay(double s, double dt_sec, double lambda);
    static double risk_pct(double decayed, double k, double x_0);
    static double clamp_score(double s, double cap);
    static double weight_for(const EngineCfg &c, const std::string &key);
};

#endif