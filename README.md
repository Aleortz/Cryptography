# Lab 1: Data Encryption Standard (DES) - Encryption & Decryption

## Overview
This repository contains the source code for Lab 1, focusing on a custom implementation of the Data Encryption Standard (DES) algorithm. The project demonstrates the core cryptographic mechanics of a symmetric-key block cipher, fully supporting both **encryption** and **decryption** of 64-bit data blocks.

## Technical Specifications

### Cryptographic Parameters
*   **Algorithm:** DES (Data Encryption Standard)
*   **Block Size:** 64-bit plaintext/ciphertext blocks
*   **Key Size:** 64-bit key (56 bits effective, 8 bits for parity)
*   **Rounds:** 16 rounds utilizing the Feistel network structure

### Core Functionality
*   **Encryption:** Converts 64-bit plaintext into 64-bit ciphertext by applying the 16 generated subkeys in forward order (Subkey 1 to Subkey 16) through the Feistel network.
*   **Decryption:** Recovers the original 64-bit plaintext from the ciphertext. It utilizes the exact same Feistel algorithm as encryption, but applies the generated subkeys in reverse order (Subkey 16 to Subkey 1).

### Implementation Details
The codebase implements all standard DES components from scratch. A notable technical design choice in this specific implementation is the approach to variable exchange operations. Rather than utilizing a conventional bitwise XOR approach for swapping, all swapping operations during the encryption and decryption pipelines are strictly implemented using an **arithmetic swap** method.

### Core Modules

**1. Key Schedule Generation (Subkey Creation)**
* First passed through Permuted Choice 1 (PC-1).
* This step drops the parity bits, reducing the effective key to 56 bits using .
* The 56-bit key is split into two 28-bit halves (C and D), which undergo circular left shifts of either 1 or 2 positions depending on the current iteration (shifting by 1 at indices 0, 1, 8, and 15).
* These shifted halves are then concatenated and passed through Permuted Choice 2 (PC-2) to extract and compress the bits into a 48-bit subkey for the round.

**2. Initial Permutation (IP)**
* The original 64-bit plaintext `x` undergoes an initial transposition mapping using the predefined `IP` matrix.
* Following the structural flow,  this permuted block is evenly divided into a 32-bit left half (L0) and a 32-bit right half (R0).

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

## How to Run

### Prerequisites
*   Python 3.x installed on your system.
*   No external libraries or dependencies are required, as the entire implementation is built using standard Python features.

### Execution
1.  Open your terminal or command prompt.
2.  Navigate to the repository directory.
3.  Execute the Python script by running the following command:
    ```bash
    python LAB1.py
    ```

### Expected Output
When executed directly, the script triggers a built-in test execution block. This demonstration process will:
*   Take a predefined Spanish plaintext string ("Hola, este es un mensaje secreto.").
*   Utilize a predefined 8-character master key ("Clave123").
*   Print the original plaintext to the console.
*   Print the master key to the console.
*   Process the encryption and print the resulting raw ciphertext characters.
*   Process the decryption and print the recovered plaintext, verifying the complete reversibility of the implemented algorithm.
