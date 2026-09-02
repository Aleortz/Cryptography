
#Variables for DES algorithm

IP: list = [58, 50, 42, 34, 26, 18, 10, 2,
          60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6,
          64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9, 1,
          59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5,
          63, 55, 47, 39, 31, 23, 15, 7]

FP: list = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18 ,58 ,26,
          33 ,1 ,41 ,9 ,49 ,17 ,57 ,25]

S_boxes: list = [
        # S1
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],  
         # S2
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
         # S3
        [[10, 0, 9, 14, 6, 3, 8, 13, 1, 4, 15, 12, 2, 11, 7, 5],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15]],
    # S4
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7 ,2 ,14]],
    # S5
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9 ,8 ,6],
         [4 ,2 ,1 ,11 ,10 ,13 ,7 ,8 ,15 ,9 ,12 ,5 ,6 ,3 ,0 ,14],
         [11 ,8 ,12 ,7 ,1 ,14 ,2 ,13 ,6 ,15 ,0 ,9 ,10 ,4 ,5 ,3]],
    # S6
        [[12 ,1 ,10 ,15 ,9 ,2 ,6 ,8 ,0 ,13 ,3 ,4 ,14 ,7 ,5 ,11],
         [10 ,15 ,4 ,2 ,7 ,12 ,9 ,5 ,6 ,1 ,13 ,14 ,0 ,11 ,3 ,8],
         [9 ,14 ,15 ,5 ,2 ,8 ,12 ,3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    # S7
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 7, 5, 10, 6, 12, 9, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2 ,15 ,8 ,6],
         [1 ,4 ,11 ,13 ,12 ,3 ,7 ,14 ,10 ,15 ,6 ,8 ,0 ,5 ,9 ,2],
         [6 ,11 ,13 ,8 ,1 ,4 ,10 ,7 ,9 ,5 ,0 ,15 ,14 ,2 ,3 ,12]],
    # S8
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13 ,8 ,11 ,5 ,6 ,15 ,0 ,3 ,4 ,7 ,2 ,12 ,1 ,10 ,14 ,9],
         [10 ,6 ,9 ,0 ,12 ,11 ,7 ,13 ,15 ,1 ,3 ,14 ,5 ,2 ,8 ,4],
         [3 ,15 ,0 ,6 ,10 ,1 ,13 ,8 ,9 ,4 ,5 ,11 ,12, 7, 2, 14]]
    ]             

#Module generator of subkeys

def Apply_PC_1(key: str) -> str:
    PC_1: list = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]

    if len(key) != 64:
        raise ValueError("Key must be 64 bits long")

    key_56_bits = ""
    for position in PC_1:
        key_56_bits += key[position - 1]

    return key_56_bits

def Apply_PC_2(key: str) -> str:
    PC_2: list = [14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32]
    
    if len(key) != 56:
        raise ValueError("Key must be 56 bits long")
    key_48_bits: str = ""
    for position in PC_2:
        key_48_bits += key[position - 1]

    return key_48_bits

def subkeys_generator(key: str) -> list:
        if len(key) != 64:
            raise ValueError("Key must be 64 bits long")
        key_56_bits: str = Apply_PC_1(key)
        subkeys: list = []
        C: str = key_56_bits[:28]
        D: str = key_56_bits[28:]
        for i in range(16):
            if i == 0 or i == 1 or i == 8 or i == 15:
                shifts = 1
            else:
                shifts = 2
            C = C[shifts:] + C[:shifts]
            D = D[shifts:] + D[:shifts]
            subkeys.append(Apply_PC_2(C + D))

        return subkeys
        

#Module DES algorithm

# function f used in DES algorithm

def function_f(Right: str, subkeys:str) -> str:
    Expansion: list = [32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1]
    Permutation: list = [16, 7, 20, 21, 29, 12, 28, 17,
        1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9,
        19, 13, 30, 6, 22, 11, 4, 25]

    #Expansion
    R_expanded: str = ""
    for position in Expansion:
        R_expanded += Right[position - 1]
    if len(R_expanded) != 48:
        raise ValueError("Expanded R must be 48 bits long")
    xor_result: str = ""
    for i in range(48): xor_result += str(int(R_expanded[i]) ^ int(subkeys[i]))

    #S-box substitution
    xor_result_6bit: list = []
    S_box_output: str = ""
    for i in range(0, 48, 6):
        xor_result_6bit.append(xor_result[i:i + 6])
    for i in range(8):
        row: int = int(xor_result_6bit[i][0] + xor_result_6bit[i][5], 2)
        col: int = int(xor_result_6bit[i][1:5], 2)
        sbox_value: int = S_boxes[i][row][col]
        S_box_output += format(sbox_value, '04b')

    #Permutation
    sbox_permuted: str = ""
    for position in Permutation:
        sbox_permuted += S_box_output[position - 1]
    return sbox_permuted

#Funtion to encrypt a 64-bit plaintext using DES algorithm

def DES_Encrypt(plaintext: str, key: str) -> str:
    if len(plaintext) != 64:
        raise ValueError("Plaintext must be 64 bits long")
    if len(key) != 64:
        raise ValueError("Key must be 64 bits long")
    
    subkeys: list = subkeys_generator(key)

    # Initial Permutation
    plaintext_permuted: str = ""
    for position in IP:
        plaintext_permuted += plaintext[position - 1]
    L: str = plaintext_permuted[:32]; 
    R: str = plaintext_permuted[32:]

    # The main DES rounds would be implemented here
    for i in range(16):
        f_result: str = function_f(R, subkeys[i])
        new_L: str =""
        for j in range(32):
            new_L += str(int(L[j]) ^ int(f_result[j]))
        L = R
        R = new_L
    # Final Permutation
    final_swap: str = R + L
    ciphertext: str = ""
    for position in FP:
        ciphertext += (final_swap)[position - 1]
    return ciphertext

#Function to decrypt a 64-bit ciphertext using DES algorithm
 
def DES_Decrypt(ciphertext: str, key: str) -> str:
    if len(ciphertext) != 64:
            raise ValueError("Ciphertext must be 64 bits long")
    if len(key) != 64:
            raise ValueError("Key must be 64 bits long")
    subkeys: list = subkeys_generator(key)
    subkeys.reverse()  # Reverse the order of subkeys for decryption

    plaintext_permuted: str = ""
    for position in IP:
        plaintext_permuted += ciphertext[position - 1]
    L: str = plaintext_permuted[:32]; 
    R: str = plaintext_permuted[32:]

    # The main DES rounds would be implemented here
    for i in range(16):
        f_result: str = function_f(R, subkeys[i])
        new_L: str =""
        for j in range(32):
            new_L += str(int(L[j]) ^ int(f_result[j]))
        L = R
        R = new_L
    # Final Permutation
    final_swap: str = R + L
    plaintext_binary: str = ""
    for position in FP:
        plaintext_binary += (final_swap)[position - 1]
    return plaintext_binary


#Convert PLAINTEXT and KEY to binary strings before calling DES_Encrypt or DES_Decrypt functions.

def text_to_binary(plaintext: str) -> str:
    binary_result = ""
    for char in plaintext:
        binary_result += format(ord(char), '08b')
    return binary_result

def pad_binary_text(binary_text: str) -> str:
    total_length = len(binary_text) 
    remainder = total_length % 64
    
    if remainder != 0:
        padding_length = 64 - remainder
        binary_text += "0" * padding_length
        
    return binary_text

def process_and_encrypt(plaintext: str, plain_key: str) -> str:

    master_key_binary = text_to_binary(plain_key)
    if len(master_key_binary) != 64:
        raise ValueError("Key must be 64 bits long after conversion to binary")

    binary_text = text_to_binary(plaintext)
    padded_binary = pad_binary_text(binary_text)
    
    final_ciphertext = ""
    total_padded_length = len(padded_binary)
    
    for i in range(0, total_padded_length, 64):
        current_block = padded_binary[i : i + 64]
        
        encrypted_block = DES_Encrypt(current_block, master_key_binary)
        final_ciphertext += encrypted_block
        
    return final_ciphertext

def process_and_decrypt(ciphertext: str, plain_key: str) -> str:
    master_key_binary = text_to_binary(plain_key)
    if len(master_key_binary) != 64:
        raise ValueError("Key must be 64 bits long after conversion to binary")

    total_length = len(ciphertext)
    if total_length % 64 != 0:
        raise ValueError("Ciphertext length must be a multiple of 64 bits")

    final_plaintext_binary= ""
    
    for i in range(0, total_length, 64):
        current_block = ciphertext[i : i + 64]
        
        decrypted_block = DES_Decrypt(current_block, master_key_binary)
        final_plaintext_binary += decrypted_block
    # Convert binary string back to text
    final_plaintext = ""
    for i in range(0, len(final_plaintext_binary), 8):
        byte = final_plaintext_binary[i:i + 8]
        final_plaintext += chr(int(byte, 2))

    return final_plaintext

#Main function to test the DES encryption
if __name__ == "__main__":
    plaintext = "Hola, este es un mensaje secreto."  
    master_key = "Clave123"  # 
    ciphertext = process_and_encrypt(plaintext, master_key)
    print(f"Plaintext: {plaintext}")
    print(f"Key: {master_key}")
    print(f"Ciphertext: {ciphertext}")

    decrypted_text = process_and_decrypt(ciphertext, master_key)
    print(f"Decrypted Text: {decrypted_text}")
