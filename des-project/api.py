from key_schedule import des_key_schedule
from des_core import des_block
def des_encrypt_block(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt a single 64-bit block using the DES algorithm.

    Args:
        key (bytes): The 8-byte (64-bit) key for encryption.
        plaintext (bytes): The 8-byte (64-bit) plaintext block to encrypt.

    Returns:
        bytes: The encrypted ciphertext block (8 bytes).
    """
    if len(key) != 8:
        raise ValueError("Key must be 8 bytes (64 bits) long")
    if len(plaintext) != 8:
        raise ValueError("Plaintext must be 8 bytes (64 bits) long")

    # Generate subkeys
    subkeys: list[int] = des_key_schedule(key)

    # Convert plaintext to integer
    block: int = int.from_bytes(plaintext, byteorder='big')

    # Encrypt the block
    encrypted_block: int = des_block(block, subkeys)

    # Convert the encrypted block back to bytes
    ciphertext: bytes = encrypted_block.to_bytes(8, byteorder='big')

    return ciphertext

def des_decrypt_block(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt a single 64-bit block using the DES algorithm.

    Args:
        key (bytes): The 8-byte (64-bit) key for decryption.
        ciphertext (bytes): The 8-byte (64-bit) ciphertext block to decrypt.

    Returns:
        bytes: The decrypted plaintext block (8 bytes).
    """
    if len(key) != 8:
        raise ValueError("Key must be 8 bytes (64 bits) long")
    if len(ciphertext) != 8:
        raise ValueError("Ciphertext must be 8 bytes (64 bits) long")

    # Generate subkeys
    subkeys: list[int] = des_key_schedule(key)

    # Convert ciphertext to integer
    block: int = int.from_bytes(ciphertext, byteorder='big')

    # Decrypt the block using the subkeys in reverse order
    decrypted_block: int = des_block(block, subkeys[::-1])

    # Convert the decrypted block back to bytes
    plaintext: bytes = decrypted_block.to_bytes(8, byteorder='big')

    return plaintext

def des_check_parity(key: bytes) -> bool:
    """Check if the key has odd parity for each byte.

    Args:
        key (bytes): The 8-byte (64-bit) key to check.

    Returns:
        bool: True if the key has odd parity for each byte, False otherwise.
    """
    if len(key) != 8:
        raise ValueError("Key must be 8 bytes (64 bits) long")

    for byte in key:
        # Count the number of 1s in the byte
        if bin(byte).count('1') % 2 == 0:  # Even number of 1s means even parity
            return False
    return True
