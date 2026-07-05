#include "math_engine.h"
#include "json.hpp"
#include <fstream>
#include <sstream>
#include <cmath>

using nlohmann::json;

std::optional<EngineCfg> MathEng::load(const std::string &path) {
    std::ifstream ifs(path);
    if (!ifs.is_open()) return std::nullopt;
    std::stringstream buf; buf << ifs.rdbuf();
    json j = json::parse(buf.str(), nullptr, false, true);
    if (j.is_discarded()) return std::nullopt;
    EngineCfg c;
    if (j.contains("engine_config")) {
        auto &e = j["engine_config"];
        if (e.contains("lambda")) c.lambda = e["lambda"].get<double>();
        if (e.contains("k")) c.k = e["k"].get<double>();
        if (e.contains("x_0")) c.x_0 = e["x_0"].get<double>();
        if (e.contains("kill_threshold")) c.kill_threshold = e["kill_threshold"].get<double>();
        if (e.contains("backprop_factor")) c.backprop_factor = e["backprop_factor"].get<double>();
        if (e.contains("backprop_max_depth")) c.backprop_max_depth = e["backprop_max_depth"].get<int>();
        if (e.contains("raw_score_cap")) c.raw_score_cap = e["raw_score_cap"].get<double>();
        if (e.contains("tick_ms")) c.tick_ms = e["tick_ms"].get<int>();
        if (e.contains("gc_dead_ttl_sec")) c.gc_dead_ttl_sec = e["gc_dead_ttl_sec"].get<double>();
        if (e.contains("gc_tomb_risk_floor")) c.gc_tomb_risk_floor = e["gc_tomb_risk_floor"].get<double>();
    }
    if (j.contains("event_weights")) {
        for (auto it = j["event_weights"].begin(); it != j["event_weights"].end(); ++it) {
            c.ev_w[it.key()] = it.value().get<double>();
        }
    }
    if (j.contains("context_multipliers")) {
        auto &m = j["context_multipliers"];
        if (m.contains("uid_0")) c.ctx_uid0 = m["uid_0"].get<double>();
        if (m.contains("cross_ns")) c.ctx_ns = m["cross_ns"].get<double>();
        if (m.contains("short_lived")) c.ctx_short = m["short_lived"].get<double>();
    }
    return c;
}

double MathEng::sigmoid_stable(double x) {
    if (x >= 0.0) {
        double z = std::exp(-x);
        return 1.0 / (1.0 + z);
    }
    double z = std::exp(x);
    return z / (1.0 + z);
}

double MathEng::apply_decay(double s, double dt_sec, double lambda) {
    if (s <= 0.0) return 0.0;
    if (dt_sec <= 0.0) return s;
    double e = std::exp(-lambda * dt_sec);
    double d = s * e;
    if (!std::isfinite(d) || d < 0.1) return 0.0;
    return d;
}

double MathEng::risk_pct(double decayed, double k, double x_0) {
    double r = sigmoid_stable(k * (decayed - x_0));
    if (r < 0.0) return 0.0;
    if (r > 1.0) return 1.0;
    return r;
}

double MathEng::clamp_score(double s, double cap) {
    if (!std::isfinite(s)) return 0.0;
    if (s < 0.0) return 0.0;
    if (s > cap) return cap;
    return s;
}

double MathEng::weight_for(const EngineCfg &c, const std::string &key) {
    auto it = c.ev_w.find(key);
    if (it == c.ev_w.end()) return 0.0;
    return it->second;
}