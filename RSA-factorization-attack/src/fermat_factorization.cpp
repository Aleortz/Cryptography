#include "factorization.h"
#include <cmath>

using namespace std;

namespace rsa_attack {

	std::pair<uint64_t, uint64_t> fermat_factorization(uint64_t n, uint64_t* iterations) {
        uint64_t a = static_cast<uint64_t>(std::ceil(std::sqrt(n)));
        uint64_t b2 = a * a - n;
        uint64_t b = static_cast<uint64_t>(std::round(std::sqrt(b2)));
        uint64_t count = 0;

        while (b * b != b2) {
            a++;
            b2 = a * a - n;
            b = static_cast<uint64_t>(std::round(std::sqrt(b2)));
            count++;
        }

        if (iterations != nullptr) {
            *iterations = count;
        }

        return {a - b, a + b};
    }

}