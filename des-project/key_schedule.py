from permutation import permute 

def Apply_PC_1(key: int ) -> int:
    PC_1: list = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]

    if key.bit_length() > 64:
        raise ValueError("Key must be 64 bits long")

    key_56_bits:int = permute(key, tuple(PC_1), 64)

    return key_56_bits

def Apply_PC_2(key: int) -> int:
    PC_2: list = [14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32]
    
    if key.bit_length() > 56:
        raise ValueError("Key must be 56 bits long")
    key_48_bits:int = permute(key, tuple(PC_2), 56)

    return key_48_bits

def des_key_schedule(key: bytes) -> list[int]:
    """Generate the 16 subkeys for DES encryption.

    Args:
        key (int): The original 64-bit key.

    Returns:
        list[int]: A list of 16 subkeys, each 48 bits long.
    """
    if len(key) != 8:
        raise ValueError("Key must be 8 bytes (64 bits) long")
    
    # Apply PC-1 to get the 56-bit key
    key_56_bits: int = Apply_PC_1(int.from_bytes(key, byteorder='big'))
    subkeys: list[int] = []


    C: int = (key_56_bits >> 28) & 0xFFFFFFF
    D: int = key_56_bits & 0xFFFFFFF
    for i in range(16):
        if i == 0 or i == 1 or i == 8 or i == 15:
            shifts = 1
        else:
            shifts = 2
        C = ((C << shifts)& 0xFFFFFFF) | (C >> (28 - shifts))
        D = (((D << shifts) & 0xFFFFFFF) | (D >> (28 - shifts)))
        combined_key: int = (C << 28) | D

        permuted_key: int = Apply_PC_2(combined_key)
        subkeys.append(permuted_key)
    return subkeys


