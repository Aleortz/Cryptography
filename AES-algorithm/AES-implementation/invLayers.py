from _2BytesMul import g_mul

def inv_sub_bytes(state, inv_sbox):
    """Replace the bytes using the inverse S-Box."""
    for i in range(len(state)):
        state[i] = inv_sbox[state[i]]
    return state

def inv_shift_rows(state):
    """Reverse the ShiftRows operation."""
    # Row 0: Same position (no shift)
    
    # Row 1: position to the right
    state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
    
    # Row 2: positions to the right
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    
    # Row 3: positions to the right
    state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]
    
    return state

def inv_mix_columns(state):
    """Multiply by the inverse matrix in GF(2^8)."""
    for i in range(4):
        c = i * 4
        b0 = state[c]
        b1 = state[c+1]
        b2 = state[c+2]
        b3 = state[c+3]
        
        # The inverse matrix uses 0x0E (14), 0x0B (11), 0x0D (13) and 0x09 (9)
        state[c]   = g_mul(0x0E, b0) ^ g_mul(0x0B, b1) ^ g_mul(0x0D, b2) ^ g_mul(0x09, b3)
        state[c+1] = g_mul(0x09, b0) ^ g_mul(0x0E, b1) ^ g_mul(0x0B, b2) ^ g_mul(0x0D, b3)
        state[c+2] = g_mul(0x0D, b0) ^ g_mul(0x09, b1) ^ g_mul(0x0E, b2) ^ g_mul(0x0B, b3)
        state[c+3] = g_mul(0x0B, b0) ^ g_mul(0x0D, b1) ^ g_mul(0x09, b2) ^ g_mul(0x0E, b3)
        
    return state