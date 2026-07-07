#ifndef EDR_MATH_ENGINE_H
#define EDR_MATH_ENGINE_H

#include <string>
#include <unordered_map>
#include <vector>
#include <optional>
#include <cstdint>

enum {
    CAT_LIFECYCLE = 0,
    CAT_EXECUTION,
    CAT_MEMORY,
    CAT_PRIVILEGE,
    CAT_EVASION,
    CAT_C2,
    CAT_COUNT
};

struct CatParams {
    double max_llr = 1.0;
    double scale = 2.0;
    double half_life = 45.0;
};

struct EngineCfg {
    double prior_logodds = -6.0;
    double seeded_prior_extra = -2.0;
    double corrob_coeff = 1.2;
    double active_floor = 0.6;
    double badge_floor = 0.20;
    double kill_threshold = 0.92;
    double backprop_factor = 0.25;
    int    backprop_max_depth = 3;
    double warmup_sec = 15.0;
    double dwell_sec = 4.0;
    int    tick_ms = 250;
    double gc_base_ttl_sec = 30.0;
    double gc_peak_ttl_coeff = 60.0;
    double gc_tomb_risk_floor = 0.10;
    double gc_forensic_keep = 0.40;
    CatParams cats[CAT_COUNT];
    std::unordered_map<std::string, double> ev_llr;
    double ctx_uid0 = 1.5;
    double ctx_ns = 1.3;
    double ctx_short = 1.2;
    std::vector<std::string> masq_names;
    std::vector<std::string> exempt_comms;
    bool prompt_enabled = false;
    double prompt_threshold = 0.70;
    bool auto_kill_enabled = false;
    std::string allow_action = "none";
    std::string deny_action = "freeze";
    std::string kill_action = "kill";};

class MathEng {
public:
    static std::optional<EngineCfg> load(const std::string &path);
    static double sigmoid_stable(double x);
    static double decay_accum(double a, double dt_sec, double half_life);
    static double cat_contrib(double accum, double max_llr, double scale);
    static double llr_for(const EngineCfg &c, const std::string &key);
};

#endif