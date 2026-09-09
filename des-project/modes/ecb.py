import sys
import os

from padding import pkcs7_pad, pkcs7_unpad

sys.path.append('C:\\Users\\alejo\\SEMESTER_2_2026\\Cryptography\\des-project\\deslib')

from des_core import des_block
from api import des_encrypt_block, des_decrypt_block


def des_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:

    """Encrypt data using DES in ECB mode.

    Args:
        key (bytes): The 8-byte (64-bit) key for encryption.
        plaintext (bytes): The plaintext data to encrypt. Must be a multiple of 8 bytes.

    Returns:
        bytes: The encrypted ciphertext.
    """
    if len(key) != 8:
        raise ValueError("Key must be 8 bytes (64 bits) long")
    
    padded_plaintext = pkcs7_pad(plaintext, 8)

    ciphertext: bytes = b''
    for i in range(0, len(padded_plaintext), 8):
        block: bytes = padded_plaintext[i:i+8]
        encrypted_block: bytes = des_encrypt_block(key, block)
        ciphertext += encrypted_block

    return ciphertext

def des_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:

    """Decrypt data using DES in ECB mode.

    Args:
        key (bytes): The 8-byte (64-bit) key for decryption.
        ciphertext (bytes): The ciphertext data to decrypt. Must be a multiple of 8 bytes.

    Returns:
        bytes: The decrypted plaintext.
    """
    if len(key) != 8:
        raise ValueError("Key must be 8 bytes (64 bits) long")
    if len(ciphertext) % 8 != 0:
        raise ValueError("Ciphertext length must be a multiple of 8 bytes")

    plaintext: bytes = b''
    for i in range(0, len(ciphertext), 8):
        block: bytes = ciphertext[i:i+8]
        decrypted_block: bytes = des_decrypt_block(key, block)
        plaintext += decrypted_block

    return pkcs7_unpad(plaintext, 8)
