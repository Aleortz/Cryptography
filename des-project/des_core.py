from permutation import permute
from feistel import feistel_f

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

def des_block(block: int, subkeys: list[int]) -> int:
    """Encrypt or decrypt a single 64-bit block using the DES algorithm.

    Args:
        block (int): The 64-bit block to encrypt or decrypt.
        subkeys (list[int]): A list of 16 subkeys, each 48 bits long.

    Returns:
        int: The encrypted or decrypted 64-bit block.
    """
    # Step 1: Initial Permutation
    permuted_block: int = permute(block, tuple(IP), 64)

    # Step 2: Split into left and right halves
    left: int = (permuted_block >> 32) & 0xFFFFFFFF
    right: int = permuted_block & 0xFFFFFFFF

    # Step 3: Perform 16 rounds of the Feistel function
    for i in range(16):
        temp_right: int = right
        right = left ^ feistel_f(right, subkeys[i])
        left = temp_right

    # Step 4: Combine the halves and apply the final permutation
    combined_block: int = (right << 32) | left
    final_block: int = permute(combined_block, tuple(FP), 64)

    return final_block