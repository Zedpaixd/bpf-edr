#ifndef EDR_SHA256_H
#define EDR_SHA256_H

#include <string>
#include <cstdint>
#include <cstddef>

class Sha256 {
public:
    Sha256();
    void reset();
    void update(const void *data, std::size_t len);
    std::string hex();
    static std::string file_hex(const std::string &path, bool &ok);
    static std::string bytes_hex(const void *data, std::size_t len);
private:
    void block(const std::uint8_t *p);
    std::uint32_t h_[8];
    std::uint8_t buf_[64];
    std::uint64_t total_;
    std::size_t buflen_;
};

#endif