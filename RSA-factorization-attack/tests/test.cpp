#include <iostream>
#include <cassert>
#include <cmath>
#include <string>
#include "factorization.h"
#include "decrypto.h"

using namespace std;

// Helper function for integer square root as required by the rubric
uint64_t integer_sqrt(uint64_t n) {
    return static_cast<uint64_t>(std::sqrt(n));
}

void run_all_tests() {
    cout << "========================================\n";
    cout << "[*] STARTING AUTOMATIC TESTS\n";
    cout << "========================================\n\n";

    // 1. Greatest Common Divisor (GCD) Test
    int64_t t, s;
    int64_t gcd_val = rsa_crypto::extended_gcd(48, 18, t, s);
    cout << "[1] GCD Test\n";
    cout << "    Inputs: a=48, b=18\n";
    cout << "    Calculated GCD: " << gcd_val << "\n";
    assert(gcd_val == 6);
    cout << "    -> PASSED\n\n";

    // 2. Modular Inverse Test
    int64_t inv = rsa_crypto::mod_inverse(17, 3120);
    cout << "[2] Modular Inverse Test\n";
    cout << "    Inputs: a=17, mod=3120\n";
    cout << "    Calculated Inverse: " << inv << "\n";
    assert(inv == 2753);
    cout << "    -> PASSED\n\n";

    // 3. Integer Square Root Test
    cout << "[3] Integer Square Root Test\n";
    cout << "    Sqrt(25) = " << integer_sqrt(25) << " (Expected: 5)\n";
    cout << "    Sqrt(26) = " << integer_sqrt(26) << " (Expected: 5 - truncated)\n";
    cout << "    Sqrt(3233) = " << integer_sqrt(3233) << " (Expected: 56)\n";
    assert(integer_sqrt(25) == 5);
    assert(integer_sqrt(26) == 5);
    assert(integer_sqrt(3233) == 56);
    cout << "    -> PASSED\n\n";

    // Standard RSA test parameters
    uint64_t n = 3233;
    uint64_t expected_p = 53; 
    uint64_t expected_q = 61; 

    // Lambda function to validate factorization outputs and verify pq = n
    auto check_factors = [n, expected_p, expected_q](std::pair<uint64_t, uint64_t> factors, const string& algo) {
        uint64_t p = factors.first;
        uint64_t q = factors.second;
        cout << "    " << algo << " recovered: p=" << p << ", q=" << q << "\n";
        cout << "    Verification (p * q): " << p * q << " (Expected n: " << n << ")\n";
        
        // 5. Factor Verification Test: pq = n
        assert(p * q == n); 
        assert((p == expected_p && q == expected_q) || (p == expected_q && q == expected_p));
    };

    // 4. The three factorization algorithms Tests
    cout << "[4 & 5] Factorization Algorithms Test (n=3233)\n";
    check_factors(rsa_attack::trial_division(n), "Trial Division");
    cout << "    -> Trial Division: PASSED\n";
    
    check_factors(rsa_attack::fermat_factorization(n), "Fermat");
    cout << "    -> Fermat Factorization: PASSED\n";
    
    check_factors(rsa_attack::pollards_rho(n), "Pollard's Rho");
    cout << "    -> Pollard's Rho: PASSED\n\n";

    // 6. RSA Encryption/Decryption Consistency Test
    uint64_t e = 17;
    uint64_t m_original = 1977;
    uint64_t phi_n = (expected_p - 1) * (expected_q - 1);
    uint64_t d = rsa_crypto::mod_inverse(e, phi_n);
    
    cout << "[6] RSA Consistency Test\n";
    cout << "    Original Message (m)  : " << m_original << "\n";
    
    // Encrypt: c = m^e mod n
    uint64_t c = rsa_crypto::square_and_multiply(m_original, e, n);
    cout << "    Encrypted Ciphertext(c): " << c << "\n";
    
    // Decrypt: m = c^d mod n
    uint64_t m_decrypted = rsa_crypto::square_and_multiply(c, d, n);
    cout << "    Decrypted Message (m'): " << m_decrypted << "\n";
    
    // Consistency verification
    assert(m_original == m_decrypted);
    cout << "    -> PASSED\n\n";

}

int main() {
    run_all_tests();
    return 0;
}