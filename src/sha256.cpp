#include "sha256.h"
#include <cstring>
#include <cstdio>

static const std::uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static inline std::uint32_t ror(std::uint32_t x, std::uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

Sha256::Sha256() { reset(); }

void Sha256::reset() {
    h_[0]=0x6a09e667; h_[1]=0xbb67ae85; h_[2]=0x3c6ef372; h_[3]=0xa54ff53a;
    h_[4]=0x510e527f; h_[5]=0x9b05688c; h_[6]=0x1f83d9ab; h_[7]=0x5be0cd19;
    total_ = 0; buflen_ = 0;
}

void Sha256::block(const std::uint8_t *p) {
    std::uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((std::uint32_t)p[i*4] << 24) | ((std::uint32_t)p[i*4+1] << 16)
             | ((std::uint32_t)p[i*4+2] << 8) | ((std::uint32_t)p[i*4+3]);
    for (int i = 16; i < 64; i++) {
        std::uint32_t s0 = ror(w[i-15],7) ^ ror(w[i-15],18) ^ (w[i-15] >> 3);
        std::uint32_t s1 = ror(w[i-2],17) ^ ror(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    std::uint32_t a=h_[0],b=h_[1],c=h_[2],d=h_[3],e=h_[4],f=h_[5],g=h_[6],h=h_[7];
    for (int i = 0; i < 64; i++) {
        std::uint32_t S1 = ror(e,6) ^ ror(e,11) ^ ror(e,25);
        std::uint32_t ch = (e & f) ^ (~e & g);
        std::uint32_t t1 = h + S1 + ch + K[i] + w[i];
        std::uint32_t S0 = ror(a,2) ^ ror(a,13) ^ ror(a,22);
        std::uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        std::uint32_t t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h_[0]+=a; h_[1]+=b; h_[2]+=c; h_[3]+=d; h_[4]+=e; h_[5]+=f; h_[6]+=g; h_[7]+=h;
}

void Sha256::update(const void *data, std::size_t len) {
    const std::uint8_t *p = static_cast<const std::uint8_t *>(data);
    total_ += len;
    while (len > 0) {
        std::size_t take = 64 - buflen_;
        if (take > len) take = len;
        std::memcpy(buf_ + buflen_, p, take);
        buflen_ += take; p += take; len -= take;
        if (buflen_ == 64) { block(buf_); buflen_ = 0; }
    }
}

std::string Sha256::hex() {
    std::uint64_t bits = total_ * 8;
    std::uint8_t pad = 0x80;
    update(&pad, 1);
    std::uint8_t zero = 0;
    while (buflen_ != 56) update(&zero, 1);
    std::uint8_t lenbuf[8];
    for (int i = 0; i < 8; i++) lenbuf[i] = (std::uint8_t)(bits >> (56 - i*8));
    update(lenbuf, 8);
    char out[65];
    for (int i = 0; i < 8; i++)
        std::snprintf(out + i*8, 9, "%08x", h_[i]);
    out[64] = 0;
    return std::string(out);
}

std::string Sha256::bytes_hex(const void *data, std::size_t len) {
    Sha256 s;
    s.update(data, len);
    return s.hex();
}

std::string Sha256::file_hex(const std::string &path, bool &ok) {
    ok = false;
    std::FILE *f = std::fopen(path.c_str(), "rb");
    if (!f) return std::string();
    Sha256 s;
    std::uint8_t buf[65536];
    std::size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) s.update(buf, n);
    bool err = std::ferror(f) != 0;
    std::fclose(f);
    if (err) return std::string();
    ok = true;
    return s.hex();
}