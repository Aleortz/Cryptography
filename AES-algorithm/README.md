# Advanced Encryption Standard (AES) Implementation

This repository contains a native, from-scratch implementation of the AES (Advanced Encryption Standard) cryptographic algorithm. It was developed for the Cryptography laboratory at the School of Mathematical and Computational Sciences, Yachay Tech University.

The project supports **128-bit, 192-bit, and 256-bit** key sizes, executing all state transformations (SubBytes, ShiftRows, MixColumns, AddRoundKey) and Galois Field GF(2^8) polynomial arithmetic in strict compliance with the FIPS-197 standard. The primary focus is evaluating the mathematical core and benchmarking performance (throughput) without high-level abstractions.

## Project Structure

The codebase is modularized to separate pure cryptographic logic from validation and benchmarking scripts:

* **`AES-implementacion/`**: Main directory for the cryptographic core.
  * `AES_implementation.py`: Contains the high-level `cipher(plaintext, key)` and `decipher(ciphertext, key)` functions.
  * Layer modules: Individual files for `key_expansion`, `add_round_key`, `sub_bytes`, `shift_rows`, `mix_columns`, and their respective inverse operations.
* **`pruebas/`**: Directory for experimental evaluation and unit testing.
  * `test_libreria.py`: Validation script that cross-references the custom encryption engine against the standard library using an adapted ECB mode and PKCS#7 padding.
  * `benchmark.py`: Performance evaluation script measuring throughput (MB/s) by processing synthetic payloads of 1 MB, 10 MB, and 100 MB.

## Requirements and Dependencies

The core encryption engine is written in pure Python and requires no external dependencies to function. However, to run the validation suite and verify mathematical exactness against industry standards, the following library is required:

* **Python 3.8+**
* **PyCryptodome**: Used exclusively in the testing environment (`pruebas/test_libreria.py`) to apply PKCS#7 padding and generate benchmark verification vectors.

Install the testing dependency via pip:
```bash
pip install pycryptodome