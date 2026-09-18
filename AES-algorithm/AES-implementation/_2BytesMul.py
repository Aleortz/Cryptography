def g_mul(a: int, b: int) -> int:
    """Multiplication by two bytes in GF(2^8) using the AES irreducible polynomial."""
    p: int = 0
    for _ in range(8):
        # If the least significant bit of 'b' is 1, we add (XOR) 'a' to the result 
        if b & 1:
            p ^= a
        #calculate the high bit of 'a' to check for overflow
        high_bit_set: int = a & 0x80
        a <<= 1
        # If there was an overflow (the degree reached x^8), reduce with the AES polynomial (0x1B)
        if high_bit_set:
            a ^= 0x1B
        a &= 0xFF
        # `Divide` b by 2 (shift right) to process the next bit
        b >>= 1

    return p