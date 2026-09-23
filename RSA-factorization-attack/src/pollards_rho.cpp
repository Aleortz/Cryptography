#include "factorization.h"
#include <numeric> 

using namespace std;

namespace rsa_attack {

    // pseudo-random polynomial function 
    uint64_t polynomial(uint64_t x, uint64_t n) {
        // We use a 128-bits data type for intermediate calculations.
        //This prevent an overflow when squaring large 64-bits values.
        unsigned __int128 x128 = x;
        return (uint64_t)((x128 * x128 + 1) % n);
    }

    pair<uint64_t, uint64_t> pollards_rho(uint64_t n) {
        if (n % 2 == 0) return {2, n / 2};
        if (n == 1) return {1, 1};

        uint64_t x = 2; //  slow pointer 
        uint64_t y = 2; // fast pointer 
        uint64_t d = 1; // GCD

        // We continue until the GCD is greater than 1
        while (d == 1) {
            // one-iteration advance 
            x = polynomial(x, n);
            
            // two-iteration advance
            y = polynomial(polynomial(y, n), n);

            // Calculate the absolute difference |x - y|
            uint64_t diff = (x > y) ? (x - y) : (y - x);
            
            // We evaluate the greatest common divisor modulo n 
            d = std::gcd(diff, n);
        }

        // if d happens to be exactly n, we find a trivial cycle and the algorithm fails.
		if (d == n) {
            return {1, n}; 
        }

        return {d, n / d};
    }
}