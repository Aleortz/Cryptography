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
1.  **Key Schedule Generation:** Implements Permuted Choice 1 (PC-1), circular left shifts, and Permuted Choice 2 (PC-2) to generate the sixteen 48-bit subkeys required for both processes.
2.  **Initial Permutation (IP):** Rearranges the 64-bit input block before entering the Feistel rounds.
3.  **Feistel Function (f):** 
    *   **Expansion (E):** Expands the 32-bit right half to 48 bits.
    *   **Key Mixing:** XORs the expanded data with the round subkey.
    *   **Substitution:** Passes the data through the 8 distinct S-boxes to compress it back to 32 bits, providing non-linearity.
    *   **Permutation (P):** Applies the final permutation within the function.
4.  **Final Permutation (IP-1):** Applies the inverse of the initial permutation to produce the final 64-bit block (either ciphertext or plaintext, depending on the operation).

## Academic Context
Developed as part of the Cryptography course requirements for the 7th semester.

