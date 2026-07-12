#ifndef EDR_REPUTATION_H
#define EDR_REPUTATION_H

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

enum RepKind { REP_BLACKLIST = 0, REP_WHITELIST = 1 };

struct RepEntry {
    std::string hash;
    std::string name;
    std::string path;
    std::string added_tstr;
    std::uint8_t kind = REP_BLACKLIST;
    bool paused = false;
};

class Reputation {
public:
    explicit Reputation(std::string store_path);
    void load();
    bool save();
    std::string resolve_exe(std::uint32_t pid) const;
    static std::string hash_of_pid(std::uint32_t pid, bool &ok);
    static std::string hash_of_file(const std::string &path, bool &ok);
    bool is_blacklisted(const std::string &hash) const;
    bool is_whitelisted(const std::string &hash) const;
    bool add(std::uint8_t kind, const std::string &hash,
             const std::string &name, const std::string &path);
    bool remove(const std::string &hash, std::uint8_t kind);
    bool set_paused(const std::string &hash, std::uint8_t kind, bool paused);
    std::vector<RepEntry> list() const;
    std::size_t count() const;
    bool tamper_flagged() const { return tamper_; }
    std::string store_path() const { return path_; }

private:
    std::string key(std::uint8_t kind, const std::string &hash) const;
    bool set_immutable(bool on) const;
    std::string compute_checksum() const;
    std::string path_;
    mutable std::mutex mtx_;
    std::unordered_map<std::string, RepEntry> entries_;
    bool tamper_ = false;
    bool immutable_supported_ = false;
};

#endif