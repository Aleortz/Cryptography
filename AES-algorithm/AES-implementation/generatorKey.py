RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

def key_expansion(key, sbox) -> list[int]:
    """
    Expands a 16, 24, or 32-byte key into the full set of round keys for AES-128/192/256.
    """
    nk = len(key) // 4  # 4 for AES-128, 6 for AES-192, 8 for AES-256
    
    if nk == 4:
        nr = 10
    elif nk == 6:
        nr = 12
    elif nk == 8:
        nr = 14
    else:
        raise ValueError("Invalid key size. Must be 16, 24, or 32 bytes.")

    expanded_key = list(key)
    bytes_generados = len(key)
    ronda_rcon = 1
    
    #Total number of bytes needed = (Rounds + 1) * 16 bytes per round
    total_bytes = (nr + 1) * 16

    while bytes_generados < total_bytes:
        temp = expanded_key[-4:]
        
        # Evaluate the current word (32 bits)
        palabra_actual = bytes_generados // 4
        
        # Condition 1: Begin a new block Nk (RotWord + SubWord + Rcon)
        if palabra_actual % nk == 0:
            temp = [temp[1], temp[2], temp[3], temp[0]]
            temp = [sbox[b] for b in temp]
            temp[0] ^= RCON[ronda_rcon]
            ronda_rcon += 1
            
        # Condition 2: Rule special to AES-256 (half the block size)
        elif nk == 8 and palabra_actual % nk == 4:
            temp = [sbox[b] for b in temp]  # Only SubWord

        # XOR with the word that is Nk positions behind
        for i in range(4):
            nuevo_byte = expanded_key[bytes_generados - (nk * 4) + i] ^ temp[i]
            expanded_key.append(nuevo_byte)

        bytes_generados += 4

    return expanded_key