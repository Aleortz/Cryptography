import sys
import os

from padding import pkcs7_pad, pkcs7_unpad
sys.path.append('C:\\Users\\alejo\\SEMESTER_2_2026\\Cryptography\\des-project\\deslib')
from des_core import des_block
from api import des_encrypt_block, des_decrypt_block

def des_cbc_encrypt(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    """Encrypt data using DES in CBC mode.

    Args:
        key (bytes): The 8-byte (64-bit) key for encryption.
        plaintext (bytes): The plaintext data to encrypt. Must be a multiple of 8 bytes.
        iv (bytes): The 8-byte (64-bit) initialization vector.

    Returns:
        bytes: The encrypted ciphertext.
    """
    if len(key) != 8:
        raise ValueError("Key must be 8 bytes (64 bits) long")
    if len(iv) != 8:
        raise ValueError("Initialization vector (IV) must be 8 bytes (64 bits) long")

    padded_plaintext = pkcs7_pad(plaintext, 8)
    ciphertext: bytes = b''
    previous_block: bytes = iv

    for i in range(0, len(padded_plaintext), 8):
        block: bytes = padded_plaintext[i:i+8]
        # XOR with the previous ciphertext block (or IV for the first block)
        xor_block: bytes = bytes(a ^ b for a, b in zip(block, previous_block))
        encrypted_block: bytes = des_encrypt_block(key, xor_block)
        ciphertext += encrypted_block
        previous_block = encrypted_block

    return ciphertext

def des_cbc_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    """Decrypt data using DES in CBC mode.

    Args:
        key (bytes): The 8-byte (64-bit) key for decryption.
        ciphertext (bytes): The ciphertext data to decrypt. Must be a multiple of 8 bytes.
        iv (bytes): The 8-byte (64-bit) initialization vector.

    Returns:
        bytes: The decrypted plaintext.
    """
    if len(key) != 8:
        raise ValueError("Key must be 8 bytes (64 bits) long")
    if len(ciphertext) % 8 != 0:
        raise ValueError("Ciphertext length must be a multiple of 8 bytes")
    if len(iv) != 8:
        raise ValueError("Initialization vector (IV) must be 8 bytes (64 bits) long")

    plaintext: bytes = b''
    previous_block: bytes = iv

    for i in range(0, len(ciphertext), 8):
        block: bytes = ciphertext[i:i+8]
        decrypted_block: bytes = des_decrypt_block(key, block)
        # XOR with the previous ciphertext block (or IV for the first block)
        xor_block: bytes = bytes(a ^ b for a, b in zip(decrypted_block, previous_block))
        plaintext += xor_block
        previous_block = block

    return pkcs7_unpad(plaintext, 8)

#Example usage:
if __name__ == "__main__":
    key_hex = '133457799BBCDFF1'
    key = bytes.fromhex(key_hex)
    iv = b'\x00\x00\x00\x00\x00\x00\x00\x00'
    plaintext = b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
    print(f"Key: {key.hex()}")
    print(f"IV: {iv.hex()}")
    print(f"Plaintext: {plaintext.hex()}")
    ciphertext = des_cbc_encrypt(key, plaintext, iv)
    print(f"Ciphertext: {ciphertext.hex()}")
    decrypted_text = des_cbc_decrypt(key, ciphertext, iv)
    print(f"Decrypted text: {decrypted_text.hex()}")