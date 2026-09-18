import sys
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

sys.path.append('C:\\Users\\alejo\\SEMESTER_2_2026\\Cryptography\\AES-algorithm\\AES-implementation')

from AES_implementation import cipher, decipher

def custom_ecb_encrypt(pt_bytes, key_list):
    """Encrypts arbitrary length data by dividing it into 16-byte blocks (ECB mode)."""
    ct_bytes = bytearray()
    for i in range(0, len(pt_bytes), 16):
        block = list(pt_bytes[i:i+16])
        ct_block = cipher(block, key_list)
        ct_bytes.extend(ct_block)
    return bytes(ct_bytes)

def custom_ecb_decrypt(ct_bytes, key_list):
    """Decrypts arbitrary length data by dividing it into 16-byte blocks (ECB mode)."""
    pt_bytes = bytearray()
    for i in range(0, len(ct_bytes), 16):
        block = list(ct_bytes[i:i+16])
        pt_block = decipher(block, key_list)
        pt_bytes.extend(pt_block)
    return bytes(pt_bytes)

def test_against_library():
    # 1. Request plaintext from the user
    user_input = input("Enter the plaintext to encrypt: ")
    raw_pt_bytes = user_input.encode('utf-8')
    
    # Apply PKCS#7 padding to ensure the plaintext is a multiple of 16 bytes (128 bits)
    pt_bytes = pad(raw_pt_bytes, 16)
    
    print(f"\nOriginal text: '{user_input}'")
    print(f"Padded plaintext (hex): {pt_bytes.hex()}\n")

    # Define key sizes in bytes (128, 192, and 256 bits)
    key_sizes = {"AES-128": 16, "AES-192": 24, "AES-256": 32}
    
    for name, size in key_sizes.items():
        print(f"--- Testing {name} ---")
        
        # 2. Generate random key using the OS
        key_bytes = os.urandom(size)
        key_list = list(key_bytes)
        
        # 3. Encrypt and Decrypt with the official library (PyCryptodome)
        aes_lib = AES.new(key_bytes, AES.MODE_ECB)
        ct_lib_bytes = aes_lib.encrypt(pt_bytes)
        pt_lib_bytes = aes_lib.decrypt(ct_lib_bytes)
        
        # 4. Encrypt and Decrypt with your custom implementation
        ct_custom_bytes = custom_ecb_encrypt(pt_bytes, key_list)
        pt_custom_bytes = custom_ecb_decrypt(ct_custom_bytes, key_list)
        
        # 5. Remove padding and convert to plain text
        try:
            pt_lib_unpadded = unpad(pt_lib_bytes, 16)
            pt_custom_unpadded = unpad(pt_custom_bytes, 16)
            
            pt_lib_text = pt_lib_unpadded.decode('utf-8')
            pt_custom_text = pt_custom_unpadded.decode('utf-8')
        except ValueError as e:
            print("=> ERROR: Padding is incorrect or decryption failed.")
            continue
            
        # 6. Display the results
        print(f"Key (hex):                 {key_bytes.hex()}")
        print(f"Library Ciphertext (hex):  {ct_lib_bytes.hex()}")
        print(f"Custom Ciphertext (hex):   {ct_custom_bytes.hex()}")
        print(f"Library Decrypted (text):  '{pt_lib_text}'")
        print(f"Custom Decrypted (text):   '{pt_custom_text}'")
        
        # 7. Verification
        is_cipher_equal = (ct_lib_bytes == ct_custom_bytes)
        is_decipher_equal = (pt_lib_bytes == pt_custom_bytes)
        
        if is_cipher_equal and is_decipher_equal:
            print("=> VERIFICATION: SUCCESS - Both implementations match perfectly.\n")
        else:
            print("=> VERIFICATION: FAILED - Outputs do not match.\n")

if __name__ == "__main__":
    test_against_library()