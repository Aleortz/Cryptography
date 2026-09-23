#ifndef CRYPTO_H
#define CRYPTO_H

#include <cstdint>

namespace rsa_crypto {
    int64_t extended_gcd(int64_t a, int64_t b, int64_t &x, int64_t &y);
    int64_t mod_inverse(int64_t e, int64_t phi);
    uint64_t square_and_multiply(uint64_t base, uint64_t exp, uint64_t mod);
}

#endif