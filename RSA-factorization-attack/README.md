# RSA Factorization Attacks - Cryptography Lab 4

**Universidad Yachay Tech** | School of Mathematical and Computational Sciences

This repository contains the C++ technical implementation and experimental evaluation of factorization algorithms designed to break the RSA cryptosystem. By recovering the prime factors $p$ and $q$, the system successfully reconstructs the private key $d$ and decrypts intercepted ciphertexts.

## 1. Cryptographic Context (RSA)
The RSA cryptosystem bases its security on the computational intractability of factoring massive composite numbers. The key generation and breaking process follows this mathematics:
* **Generation:** Two large prime numbers $p$ and $q$ are selected. The public modulus $n = pq$ is calculated.
* **Totient Function:** Calculated as $\phi(n) = (p-1)(q-1)$.
* **Keys:** A public exponent $e$ coprime to $\phi(n)$ is chosen. The private key $d$ is derived by calculating the modular inverse: $d \equiv e^{-1} \pmod{\phi(n)}$.
* **Attack:** The modulus $n$ and exponent $e$ are public. If an attacker successfully factors $n$ to obtain $p$ and $q$, they can compute $\phi(n)$, apply the Extended Euclidean Algorithm to find $d$, and completely break the system's security.

## 2. Factorization Modules
The core of this laboratory evaluates three distinct algorithmic approaches to compute the factor pair $(p, q)$ from the public modulus $n$:

* **Trial Division (Linear Brute Force):**
  Iterates sequentially searching for an exact divisor of $n$. To optimize, the upper search limit is strictly bounded to $\sqrt{n}$ and unnecessary even numbers are skipped. It is highly efficient when one of the factors is very small but collapses asymptotically against large primes.
  
* **Fermat Factorization (Difference of Squares):**
  Exploits the mathematical identity $n = a^2 - b^2 = (a-b)(a+b)$. The algorithm initializes $a = \lceil\sqrt{n}\rceil$ and progressively increases until $b^2 = a^2 - n$ becomes a perfect square. It extracts the factors as $p = a-b$ and $q = a+b$. It is lethally fast when $p$ and $q$ have very close numerical values but degrades into an inefficient loop if the distance $\vert{}p - q\vert{}$ is large.

* **Pollard's Rho (Random Cycle Detection):**
  A probabilistic algorithm utilizing a pseudo-random polynomial function, typically $f(x) = (x^2 + 1) \pmod n$. It employs Floyd's cycle-finding algorithm (the tortoise and the hare) coupled with the Greatest Common Divisor (GCD) calculation. If $\gcd(\vert{}x-y\vert{}, n) = d$ where $1 < d < n$, a non-trivial factor has been found. It offers a superior time and space complexity of $O(n^{1/4})$, ideal for moduli with distant primes where Fermat fails.

## 3. Project Structure
The source code is modularized into three main directories:

```text
├── benchmark/       # Performance evaluations and iteration analysis
│   └── RSA_benchmark.cpp
├── src/             # Core cryptographic logic and attack algorithms
│   ├── factorization.h
│   ├── trial_division.cpp
│   ├── fermat_factorization.cpp
│   ├── pollards_rho.cpp
│   ├── decrypto.h
│   └── decrypto.cpp
└── tests/           # Isolated environment for automated unit testing
    └── tests.cpp
```

## 4. Environment Setup (Windows 11 + Cygwin)

The project is optimized to be compiled and executed via the Cygwin POSIX terminal on Windows 11.

**Prerequisites in the Cygwin installer:**
* `gcc-core`
* `gcc-g++` (Strict support for `-std=c++17`)
* `make` (Optional, for automation)

Ensure you open the Cygwin64 Terminal and navigate to the root of the repository using Windows mount paths (e.g., `cd /cygdrive/c/Users/YourUser/PathToRepo`).

## 5. Compiling and Executing Unit Tests

The `tests/` directory contains raw assertions (`<cassert>`) designed to abort execution if any mathematical anomaly is detected. It validates the consistency of the Modular Inverse, Extended Euclidean Algorithm, the $pq = n$ condition, and a full RSA encryption/decryption cycle.

**Compilation in Cygwin:**
```bash
g++ -std=c++17 -O3 -I./src tests/tests.cpp src/trial_division.cpp src/fermat_factorization.cpp src/pollards_rho.cpp src/decrypto.cpp -o tests/rsa_tests.exe


**Execution:**

```bash
./tests/rsa_tests.exe
```

*(A successful run will print the validation log to the console without aborting the program).*

## 6. Executing the Experimental Benchmark

The `benchmark/` directory contains the script to evaluate execution time (in nanoseconds using `<chrono>`) averaged over multiple runs. It analyzes various RSA moduli specifically generated to contrast Fermat's vulnerabilities against the probabilistic efficiency of Pollard's Rho.

**Compilation in Cygwin:**

```bash
g++ -std=c++17 -O3 -I./src benchmark/RSA_benchmark.cpp src/trial_division.cpp src/fermat_factorization.cpp src/pollards_rho.cpp src/decrypto.cpp -o benchmark/rsa_bench.exe
```

**Execution:**

```bash
./benchmark/rsa_bench.exe
```

## Authors

- Christopher Alejandro Ortiz Bustillos