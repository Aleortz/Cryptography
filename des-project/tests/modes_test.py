import sys
import os

sys.path.append('C:\\Users\\alejo\\SEMESTER_2_2026\\Cryptography\\des-project\\modes')

from padding import pkcs7_pad, pkcs7_unpad
from ecb import des_ecb_encrypt, des_ecb_decrypt
from cbc import des_cbc_encrypt, des_cbc_decrypt

# Valid DES key with odd parity (16 hex chars = 64 bits)
PLAINTEXT: bytes = b"ABCDEFGHABCDEFGHABCDEFGHABCDEFGH"
VALID_KEY: bytes = bytes.fromhex("133457799BBCDFF1")
VALID_IV: bytes = bytes.fromhex("0123456789ABCDEF")
ALT_IV: bytes = bytes.fromhex("FEDCBA9876543210")

print(f"Plaintext: {PLAINTEXT.hex()}")
print(f"Valid Key: {VALID_KEY.hex()}")
print(f"Valid IV: {VALID_IV.hex()}")
print(f"Alternative IV: {ALT_IV.hex()}")

### Exercise 4: ECB versus CBC ###
print("\n=== Exercise 4: ECB versus CBC ===\n")
ECB_CIPHERTEXT: bytes = des_ecb_encrypt(VALID_KEY, PLAINTEXT)
print(f"Ciphertext (ECB) divided into 8-byte blocks:")
for i in range(0, len(ECB_CIPHERTEXT), 8):
    print(f"  Block {i//8 + 1}: {ECB_CIPHERTEXT[i:i+8].hex()}")
print(f"\nCiphertext (ECB) in hex: {ECB_CIPHERTEXT.hex()}")

CBC_CIPHERTEXT = des_cbc_encrypt(VALID_KEY, PLAINTEXT, VALID_IV)
print(f"Ciphertext (CBC) divided into 8-byte blocks (using VALID_IV):")
for i in range(0, len(CBC_CIPHERTEXT), 8):
    print(f"  Block {i//8 + 1}: {CBC_CIPHERTEXT[i:i+8].hex()}")

## Exercise 5: CBC with Different IVs ###
print("\n=== Exercise 5: CBC with Different IVs ===\n")
CBC_CIPHERTEXT_ALT_IV = des_cbc_encrypt(VALID_KEY, PLAINTEXT, ALT_IV)
print(f"Ciphertext (CBC with different IV) divided into 8-byte blocks (using ALT_IV):")
for i in range(0, len(CBC_CIPHERTEXT_ALT_IV), 8):
    print(f"  Block {i//8 + 1}: {CBC_CIPHERTEXT_ALT_IV[i:i+8].hex()}")

###Exercise 6: Error Propagation, change a bit in the ciphertext (ECB and CBC)###

print("\n=== Exercise 6: Error Propagation ===\n")
ECB_CIPHERTEXT_CORRUPTED = bytearray(ECB_CIPHERTEXT)
# Flip the first bit of the first byte of the first block
ECB_CIPHERTEXT_CORRUPTED[0] ^= 0x15
print(f"Corrupted Ciphertext (ECB) divided into 8-byte blocks (changing the first bit of the first byte using XOR with 0x15):")
for i in range(0, len(ECB_CIPHERTEXT_CORRUPTED), 8):
    print(f"  Block {i//8 + 1} ECB_Corrupted: {ECB_CIPHERTEXT_CORRUPTED[i:i+8].hex()}")
    print(f"  Block {i//8 + 1} ECB_Normal: {ECB_CIPHERTEXT[i:i+8].hex()}")

CBC_CIPHERTEXT_CORRUPTED = bytearray(CBC_CIPHERTEXT)
# Flip the first bit of the first byte of the first block
CBC_CIPHERTEXT_CORRUPTED[0] ^= 0x15
print(f"Corrupted Ciphertext (CBC) divided into 8-byte blocks (changing the first bit of the first byte using XOR with 0x15):")
for i in range(0, len(CBC_CIPHERTEXT_CORRUPTED), 8):
    print(f"  Block {i//8 + 1} CBC_Corrupted: {CBC_CIPHERTEXT_CORRUPTED[i:i+8].hex()}")
    print(f"  Block {i//8 + 1} CBC_Normal: {CBC_CIPHERTEXT[i:i+8].hex()}")


    
