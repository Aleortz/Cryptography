from permutation import permute
from s_boxes import sbox_lookup

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

def feistel_f(right: int, subkey: int) -> int:
    """Perform the Feistel function on the right half of the data block.

    Args:
        right (int): The right half of the data block (32 bits).
        subkey (int): The subkey for the current round (48 bits).

    Returns:
        int: The result of the Feistel function (32 bits).
    """
    # Step 1: Expansion permutation
    expanded_right: int = permute(right, tuple(Expansion), 32)

    # Step 2: XOR with subkey
    xor_result: int = expanded_right ^ subkey

    # Step 3: S-box substitution
    sbox_result: int = 0
    for i in range(8):
        six_bits: int = (xor_result >> (42 - 6 * i)) & 0x3F
        sbox_output: int = sbox_lookup(S_boxes[i], six_bits)
        sbox_result |= (sbox_output << (28 - 4 * i))

    # Step 4: Permutation P
    final_result: int = permute(sbox_result, tuple(Permutation), 32)

    return final_result

def des_round(left: int, right: int, subkey: int) -> tuple[int, int]:
    """Perform one round of the DES algorithm.

    Args:
        left (int): The left half of the data block (32 bits).
        right (int): The right half of the data block (32 bits).
        subkey (int): The subkey for the current round (48 bits).

    Returns:
        tuple[int, int]: The new left and right halves after the round.
    """
    new_left: int = right
    new_right: int = left ^ feistel_f(right, subkey)
    return new_left, new_right
