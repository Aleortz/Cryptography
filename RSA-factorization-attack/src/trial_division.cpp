#include "factorization.h"

#include <iostream>
#include <cmath>

using namespace std;

#include "factorization.h"
#include <cmath>

using namespace std;

namespace rsa_attack {

    pair<uint64_t, uint64_t> trial_division(uint64_t n) {
        if (n % 2 == 0) return {2, n / 2};

        uint64_t limit = sqrt(n);
        
        for (uint64_t i = 3; i <= limit; i += 2) {
            if (n % i == 0) {
                return {i, n / i}; 
            }
        }
        return {1, n};
    }

}