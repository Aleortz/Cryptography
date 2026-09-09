import sys
import os

# Adjust path to import your DES core functions
sys.path.append('C:\\Users\\alejo\\SEMESTER_2_2026\\Cryptography\\des-project\\deslib')
from api import des_encrypt_block
from keyspace import int_to_des_key

def brute_force_des(plaintext: bytes, ciphertext: bytes, start: int, end: int):
    """
    Perform a known-plaintext brute-force attack over a specific key range.

    Args:
        plaintext (bytes): A known 8-byte block of plaintext.
        ciphertext (bytes): The corresponding 8-byte block of ciphertext.
        start (int): The starting integer of the 56-bit key space.
        end (int): The ending integer (exclusive) of the search space.

    Returns:
        tuple: (found_key_bytes, number_of_keys_tested) if found, 
               or (None, total_tested) if not found in the range.
    """
    keys_tested = 0
    
    for candidate_int in range(start, end):
        keys_tested += 1
        
        # 1. Convert candidate integer to a valid 64-bit DES key
        candidate_key = int_to_des_key(candidate_int)
        
        # 2. Encrypt the plaintext with this candidate key
        encrypted_candidate = des_encrypt_block(candidate_key, plaintext)
        
        # 3. Check if it matches the target ciphertext
        if encrypted_candidate == ciphertext:
            return candidate_key, keys_tested
            
    return None, keys_tested