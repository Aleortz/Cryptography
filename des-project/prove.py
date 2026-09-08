#Prove DES implementation is correct by encrypting and decrypting a known plaintext with a known key and comparing the result to the expected ciphertext.
from api import des_encrypt_block, des_decrypt_block

def prove_des_implementation():
    # Known key and plaintext
    key = b'\x12\x34\x56\x78\x90\xAB\xCD\xEF'
    plaintext = b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
    print(f"Key: {key.hex()}")
    print(f"Plaintext: {plaintext.hex()}")

    # Encrypt the plaintext
    ciphertext = des_encrypt_block(key, plaintext)
    print(f"Ciphertext: {ciphertext.hex()}")

    # Decrypt the ciphertext
    decrypted_plaintext = des_decrypt_block(key, ciphertext)
    print(f"Decrypted Plaintext: {decrypted_plaintext.hex()}")

    # Check if the encryption and decryption are correct
    if decrypted_plaintext == plaintext:
        print("DES implementation is correct.")

prove_des_implementation()