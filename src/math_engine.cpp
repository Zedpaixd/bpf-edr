#include "math_engine.h"
#include "json.hpp"
#include <fstream>
#include <sstream>
#include <cmath>

using nlohmann::json;

static void set_cat_defaults(EngineCfg &c) {
    c.cats[CAT_LIFECYCLE] = { 0.3, 4.0, 20.0 };
    c.cats[CAT_EXECUTION] = { 2.0, 2.5, 45.0 };
    c.cats[CAT_MEMORY]    = { 3.0, 2.0, 60.0 };
    c.cats[CAT_PRIVILEGE] = { 3.0, 2.0, 60.0 };
    c.cats[CAT_EVASION]   = { 2.5, 2.5, 45.0 };
    c.cats[CAT_C2]        = { 1.5, 1.5, 30.0 };
}

static void load_cat(const json &j, const char *name, CatParams &p) {
    if (!j.contains(name)) return;
    auto &e = j[name];
    if (e.contains("max_llr")) p.max_llr = e["max_llr"].get<double>();
    if (e.contains("scale")) p.scale = e["scale"].get<double>();
    if (e.contains("half_life_sec")) p.half_life = e["half_life_sec"].get<double>();
}

std::optional<EngineCfg> MathEng::load(const std::string &path) {
    std::ifstream ifs(path);
    if (!ifs.is_open()) return std::nullopt;
    std::stringstream buf; buf << ifs.rdbuf();
    json j = json::parse(buf.str(), nullptr, false, true);
    if (j.is_discarded()) return std::nullopt;
    EngineCfg c;
    set_cat_defaults(c);
    if (j.contains("engine_config")) {
        auto &e = j["engine_config"];
        auto gd = [&](const char *k, double &dst){ if (e.contains(k)) dst = e[k].get<double>(); };
        auto gi = [&](const char *k, int &dst){ if (e.contains(k)) dst = e[k].get<int>(); };
        gd("prior_logodds", c.prior_logodds);
        gd("seeded_prior_extra", c.seeded_prior_extra);
        gd("corrob_coeff", c.corrob_coeff);
        gd("active_floor", c.active_floor);
        gd("badge_floor", c.badge_floor);
        gd("kill_threshold", c.kill_threshold);
        gd("backprop_factor", c.backprop_factor);
        gi("backprop_max_depth", c.backprop_max_depth);
        gd("warmup_sec", c.warmup_sec);
        gd("dwell_sec", c.dwell_sec);
        gi("tick_ms", c.tick_ms);
        gd("gc_base_ttl_sec", c.gc_base_ttl_sec);
        gd("gc_peak_ttl_coeff", c.gc_peak_ttl_coeff);
        gd("gc_tomb_risk_floor", c.gc_tomb_risk_floor);
        gd("gc_forensic_keep", c.gc_forensic_keep);
    }
    if (j.contains("categories")) {
        auto &cats = j["categories"];
        load_cat(cats, "lifecycle", c.cats[CAT_LIFECYCLE]);
        load_cat(cats, "execution", c.cats[CAT_EXECUTION]);
        load_cat(cats, "memory",    c.cats[CAT_MEMORY]);
        load_cat(cats, "privilege", c.cats[CAT_PRIVILEGE]);
        load_cat(cats, "evasion",   c.cats[CAT_EVASION]);
        load_cat(cats, "c2",        c.cats[CAT_C2]);
    }
    if (j.contains("event_llr")) {
        for (auto it = j["event_llr"].begin(); it != j["event_llr"].end(); ++it)
            c.ev_llr[it.key()] = it.value().get<double>();
    }
    if (j.contains("context_multipliers")) {
        auto &m = j["context_multipliers"];
        if (m.contains("uid_0")) c.ctx_uid0 = m["uid_0"].get<double>();
        if (m.contains("cross_ns")) c.ctx_ns = m["cross_ns"].get<double>();
        if (m.contains("short_lived")) c.ctx_short = m["short_lived"].get<double>();
    }
    if (j.contains("masquerade_names")) {
        for (auto &v : j["masquerade_names"]) c.masq_names.push_back(v.get<std::string>());
    }
    if (j.contains("exempt_comms")) {
        for (auto &v : j["exempt_comms"]) c.exempt_comms.push_back(v.get<std::string>());
    }

    if (j.contains("prompt_config")) {
        auto &p = j["prompt_config"];
        if (p.contains("enabled")) c.prompt_enabled = p["enabled"].get<bool>();
        if (p.contains("prompt_threshold")) c.prompt_threshold = p["prompt_threshold"].get<double>();
        if (p.contains("auto_kill_enabled")) c.auto_kill_enabled = p["auto_kill_enabled"].get<bool>();
        if (p.contains("allow_action")) c.allow_action = p["allow_action"].get<std::string>();
        if (p.contains("deny_action")) c.deny_action = p["deny_action"].get<std::string>();
        if (p.contains("kill_action")) c.kill_action = p["kill_action"].get<std::string>();
    }
    return c;
}

double MathEng::sigmoid_stable(double x) {
    if (x >= 0.0) { double z = std::exp(-x); return 1.0 / (1.0 + z); }
    double z = std::exp(x); return z / (1.0 + z);
}

double MathEng::decay_accum(double a, double dt_sec, double half_life) {
    if (a <= 0.0) return 0.0;
    if (dt_sec <= 0.0 || half_life <= 0.0) return a;
    double lambda = 0.6931471805599453 / half_life;
    double d = a * std::exp(-lambda * dt_sec);
    if (!std::isfinite(d) || d < 1e-4) return 0.0;
    return d;
}

double MathEng::cat_contrib(double accum, double max_llr, double scale) {
    if (accum <= 0.0 || scale <= 0.0) return 0.0;
    return max_llr * std::tanh(accum / scale);
}

double MathEng::llr_for(const EngineCfg &c, const std::string &key) {
    auto it = c.ev_llr.find(key);
    if (it == c.ev_llr.end()) return 0.0;
    return it->second;
}