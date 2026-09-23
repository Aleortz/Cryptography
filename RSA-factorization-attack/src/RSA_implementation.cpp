#include <iostream>
#include <cstdint>
#include <chrono>
#include <string>
#include "factorization.h"
#include "decrypto.h" // Updated header name as requested

using namespace std;
using namespace std::chrono;

// Template function to encapsulate the attack execution and timing
template <typename Func>
void execute_attack(const string& algo_name, Func factor_function, uint64_t n, uint64_t e, uint64_t c) {
    cout << "--------------------------------------------------\n";
    cout << "[*] Algorithm: " << algo_name << "\n";
    
    // 1. Start the high-resolution timer
    auto start_time = high_resolution_clock::now();
    
    // 2. Execute the specific factorization algorithm
    auto [p, q] = factor_function(n);
    
    // 3. Stop the timer immediately after the factors are found
    auto end_time = high_resolution_clock::now();
    
    // 4. Calculate the elapsed duration in microseconds
    auto duration = duration_cast<nanoseconds>(end_time - start_time).count();
    
    // 5. Cryptographic calculations for the private key
    uint64_t phi_n = (p - 1) * (q - 1);
    int64_t d = rsa_crypto::mod_inverse(e, phi_n);
    
    // 6. Decrypt the ciphertext using the recovered private key
    uint64_t m = rsa_crypto::square_and_multiply(c, d, n);
    
    // 7. Output all the requested metrics
    cout << "    Recovered Factors   : p = " << p << ", q = " << q << "\n";
    cout << "    Private Key Pair    : (n, d) = (" << n << ", " << d << ")\n";
    cout << "    Ciphertext (c)      : " << c << "\n";
    cout << "    Decrypted Text (m)  : " << m << "\n";
    cout << "    Execution Time      : " << duration << " nanoseconds\n";
}

int main() {
    // Initial test parameters from the lab specifications
    uint64_t n = 3233;
    uint64_t e = 17;
    uint64_t c = 2790;
    
    cout << "=== RSA FACTORIZATION ATTACK BENCHMARK ===\n";
    
    // Execute the full attack pipeline for each algorithm
    execute_attack("Trial Division", rsa_attack::trial_division, n, e, c);
    execute_attack("Fermat Factorization", rsa_attack::fermat_factorization, n, e, c);
    execute_attack("Pollard's Rho", rsa_attack::pollards_rho, n, e, c);
    
    cout << "--------------------------------------------------\n";
    
    return 0;
}