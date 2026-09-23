#include "decrypto.h"

namespace rsa_crypto {

    int64_t extended_gcd(int64_t a, int64_t n, int64_t &t, int64_t &s) {
        // Base case: when n reaches 0, we find the GCD.
        if (n == 0) {
            t = 1;
            s = 0;
            return a;
        }
        
        int64_t t1, s1;
        // Recursive call with awapped parameters
        int64_t gcd = extended_gcd(n, a % n, t1, s1);
        
        // Updating the coefficients when unwinding the recursion 
        t = s1;
        s = t1 - (a / n) * s1;
        
        return gcd;
    }

    int64_t mod_inverse(int64_t e, int64_t phi) {
        int64_t x, y;
        int64_t gcd = extended_gcd(e, phi, x, y);
        
        // If the GCD is not 1, the inverse does not exist (e and phi are not co-prime)
        if (gcd != 1) {
            return -1; 
        }
        return (x % phi + phi) % phi;
    }

	uint64_t square_and_multiply(uint64_t x, uint64_t H, uint64_t n) {
        // Handle edge cases for strict correctness
        if (H == 0) return 1;
        if (n == 1) return 0;

        // Find the index of the most significant bit (t) where h_t = 1
        int t = 63 - __builtin_clzll(H);

        // Initialization: r = x
        // We apply modulo n defensively in case the base x is initially larger than n.
        uint64_t r = x % n;
        uint64_t base_x = x % n;

        // 1 FOR i = t - 1 DOWNTO 0
        for (int i = t - 1; i >= 0; --i) {
            
            // r = r^2 mod n
            unsigned __int128 r128 = r;
            r = (uint64_t)((r128 * r128) % n);

            // Extract the current bit h_i using right shift and bitwise AND
            uint64_t h_i = (H >> i) & 1;
			
            if (h_i == 1) {
                // 1.2 r = r * x mod n
                unsigned __int128 r_times_x = r;
                r = (uint64_t)((r_times_x * base_x) % n);
            }
        }
        return r;
    }
}