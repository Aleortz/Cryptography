# Lab: DES Modes of Operation & Parallel Brute-Force Benchmark

## Overview
This repository contains the source code for the DES implementation laboratory, focusing on evaluating standard modes of operation (ECB and CBC), analyzing error propagation, and benchmarking a parallelized brute-force attack on a multi-core CPU. The project demonstrates the structural vulnerabilities of certain cryptographic modes and proves the mathematical obsolescence of a 56-bit key space against concurrent computing.

## Technical Specifications

### Cryptographic Parameters
*   **Algorithm:** DES (Data Encryption Standard)
*   **Block Size:** 64-bit plaintext/ciphertext blocks
*   **Key Size:** 64-bit key (56 bits effective, 8 bits for parity)
*   **Initialization Vector (IV):** 64-bit block utilized for Cipher Block Chaining (CBC) mode
*   **Rounds:** 16 rounds utilizing the Feistel network structure

### Core Functionality
*   **Modes of Operation:** Supports data encryption and decryption through Electronic Codebook (ECB) and Cipher Block Chaining (CBC) configurations.
*   **Error Propagation Analysis:** Simulates ciphertext corruption (bit-flipping) to demonstrate the isolated impact in ECB versus the cascading block corruption in CBC.
*   **Parallel Exhaustive Search:** Executes a known-plaintext brute-force attack, partitioning a reduced search space ($2^{20}$) across multiple CPU logical cores to measure execution time, throughput, speedup, and parallel efficiency.

### Implementation Details
The codebase implements all standard DES components. A notable technical design choice in this specific implementation is the approach to variable exchange operations. Rather than utilizing a conventional bitwise XOR approach for swapping, all swapping operations during the encryption and decryption pipelines are strictly implemented using an **arithmetic swap** method.

### Core Modules

**1. Key Schedule Generation (Subkey Creation)**
* First passed through Permuted Choice 1 (PC-1).
* This step drops the parity bits, reducing the effective key to 56 bits.
* The 56-bit key is split into two 28-bit halves (C and D), which undergo circular left shifts of either 1 or 2 positions depending on the current iteration (shifting by 1 at indices 0, 1, 8, and 15).
* These shifted halves are then concatenated and passed through Permuted Choice 2 (PC-2) to extract and compress the bits into a 48-bit subkey for the round.

**2. Initial Permutation (IP)**
* The original 64-bit plaintext `x` undergoes an initial transposition mapping using the predefined `IP` matrix.
* Following the structural flow, this permuted block is evenly divided into a 32-bit left half (L0) and a 32-bit right half (R0).

**3. Feistel Function (f) & Round Execution**
The core algorithm executes 16 identical rounds, relying on the Feistel network structure. Within each round, the right half (R) and the generated round subkey are processed through the function `f`:
* **Expansion (E):** The 32-bit R block is expanded to 48 bits using the `Expansion` array to match the current subkey's size.
* **Key Mixing:** The expanded 48-bit block is XOR-ed bit-by-bit with the 48-bit round subkey.
* **Substitution (S-boxes):** The mixed 48-bit result is divided into eight 6-bit chunks. Each chunk is evaluated by one of the 8 distinct `S_boxes`: the first and sixth bits determine the row, while the middle four bits determine the column. This process compresses the output back down to a 32-bit block.
* **Permutation (P):** The 32-bit S-box output is mapped and rearranged using the inner `Permutation` table.
* **State Update & Swap:** The final output of function `f` is XOR-ed with the left half (L) to form the new right half. To prepare for the subsequent round, the two halves are exchanged. In alignment with this implementation's specific architectural choices, this exchange is conceptually structured using an arithmetic swap operation rather than a conventional bitwise XOR sequence.

**4. Final Permutation (IP-1)**
* After the 16th round, a final exchange occurs, concatenating the R and L halves back into a single 64-bit sequence.
* This block is passed through the inverse permutation matrix (`FP`), which produces the final 64-bit output—the ciphertext `y = DES_k(x)`.

**5. Modes & Orchestration**
* **Modes Orchestrator:** Divides larger plaintexts into discrete 8-byte chunks, managing the independent block encryption (ECB) or the sequential XOR chaining with the previous block/IV (CBC).
* **Parallel Benchmark Orchestrator:** Utilizes Python's `multiprocessing` to assign equal key-space intervals to individual workers, capturing execution times to calculate parallel efficiency ($E_p$) and speedup ($S_p$).

## How to Run

### Prerequisites
*   Python 3.8+ installed on your system.
*   Standard built-in libraries (`sys`, `os`, `multiprocessing`, `time`).
*   `matplotlib` (required only for generating the graphical charts in the benchmark section).

### Execution
To execute the different parts of the laboratory, you must navigate to their respective directories.

1.  Open your terminal or command prompt.
2.  **To execute Part 1 (Modes of Operation & Error Propagation):**
    ```bash
    cd test
    python modes_test.py
    ```
3.  **To execute Part 2 (Parallel Brute-Force Benchmark):**
    ```bash
    cd ../benchmarks
    python benchmark.py
    python generar_graficas.py
    ```

### Expected Output
When the scripts are executed, the console will output the technical findings based on the laboratory tests:

**From the `test` directory (Modes of Operation):**
*   The script encrypts identical repeating plaintext blocks (`4142434445464748...`) using the Valid Key `133457799bbcdff1`.
*   It demonstrates that ECB mode produces identical ciphertext blocks (`56467e175662aff6`), exposing structural patterns, while CBC mode (using IV `0123456789abcdef`) completely masks the patterns with distinct blocks (`72ab28e79136b967`, `0d2be1c34bb3d425`, etc.).
*   Corrupting the first bit of the first ciphertext byte alters only the corresponding block in ECB mode (`43467e175662aff6`), but triggers an error propagation cascade in CBC mode.

**From the `benchmarks` directory (Brute-Force):**
*   Testing a $2^{20}$ key space sequentially (1 worker) averages 319.9990 seconds with a throughput of 3276.81 keys/s.
*   Parallel execution with 6 CPU workers scales the throughput to 16650.57 keys/s, lowering the execution time to 62.9754 seconds and achieving a speedup of 5.0813 (Parallel Efficiency: 84.69%).
*   The script calculates an extrapolation for a full $2^{56}$ DES exhaustive search, estimating a maximum theoretical recovery time ($T_{max}$) of approximately 137,000 years under the tested Python implementation.
