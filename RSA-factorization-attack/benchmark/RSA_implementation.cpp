#include <iostream>
#include <cstdint>
#include <chrono>
#include <string>
#include <iomanip>
#include <cmath>
#include "factorization.h"

using namespace std;
using namespace std::chrono;

// Ejecuta el algoritmo 3 veces y devuelve el tiempo promedio en nanosegundos[cite: 1]
template <typename Func>
long long get_average_time(Func factor_function, uint64_t n) {
    long long total_duration = 0;
    for (int i = 0; i < 3; ++i) {
        auto start_time = high_resolution_clock::now();
        factor_function(n);
        auto end_time = high_resolution_clock::now();
        total_duration += duration_cast<nanoseconds>(end_time - start_time).count();
    }
    return total_duration / 3;
}

void run_benchmark() {
    // Definición de los 4 módulos para el Ejercicio 6 y 7[cite: 1]
    struct TestModulus {
        int bits;
        uint64_t n;
        string description;
    };

    TestModulus moduli[] = {
        {33, 5234636191ULL, "Base Modulus"},
        {40, 1099511627791ULL, "Medium Modulus"},
        {45, 35184372088891ULL, "Close Primes (Fermat Trap)"},
        {45, 35184371900411ULL, "Distant Primes (Pollard's Terrain)"}
    };

    cout << "==============================================================\n";
    cout << " PART IV: EXPERIMENTAL BENCHMARK (Average of 3 runs) \n";
    cout << "==============================================================\n";
    cout << left << setw(6) << "Bits" << setw(20) << "Modulus (n)" 
         << setw(15) << "Trial Div (ns)" << setw(15) << "Fermat (ns)" 
         << setw(15) << "Pollard (ns)" << "\n";
    cout << "--------------------------------------------------------------\n";

    for (const auto& mod : moduli) {
        uint64_t n = mod.n;
        
        // Trial Division
        auto time_trial = get_average_time([](uint64_t n) { return rsa_attack::trial_division(n); }, n);
        
        // Fermat Factorization
        auto time_fermat = get_average_time([](uint64_t n) { return rsa_attack::fermat_factorization(n); }, n);
        
        // Pollard's Rho
        auto time_pollard = get_average_time([](uint64_t n) { return rsa_attack::pollards_rho(n); }, n);

        cout << left << setw(6) << mod.bits << setw(20) << n 
             << setw(15) << time_trial << setw(15) << time_fermat 
             << setw(15) << time_pollard << "\n";
    }

    cout << "\n==============================================================\n";
    cout << " PART V: FERMAT ANALYSIS (|p - q| vs Iterations) \n";
    cout << "==============================================================\n";
    
    // Evaluando los dos módulos de 45 bits[cite: 1]
    uint64_t n_close = 35184372088891ULL; // p y q cercanos
    uint64_t n_far = 35184371900411ULL;   // p y q lejanos

    uint64_t iter_close = 0, iter_far = 0;
    auto factors_close = rsa_attack::fermat_factorization(n_close, &iter_close);
    auto factors_far = rsa_attack::fermat_factorization(n_far, &iter_far);

    uint64_t dist_close = (factors_close.first > factors_close.second) ? 
                          (factors_close.first - factors_close.second) : 
                          (factors_close.second - factors_close.first);
                          
    uint64_t dist_far = (factors_far.first > factors_far.second) ? 
                        (factors_far.first - factors_far.second) : 
                        (factors_far.second - factors_far.first);

    cout << "1. Close Primes (n = " << n_close << ")\n";
    cout << "   |p - q|    : " << dist_close << "\n";
    cout << "   Iterations : " << iter_close << "\n\n";

    cout << "2. Distant Primes (n = " << n_far << ")\n";
    cout << "   |p - q|    : " << dist_far << "\n";
    cout << "   Iterations : " << iter_far << "\n";
    cout << "==============================================================\n";
}

int main() {
    run_benchmark();
    return 0;
}