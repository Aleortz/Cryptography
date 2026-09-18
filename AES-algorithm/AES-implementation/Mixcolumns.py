from _2BytesMul import g_mul

def mix_columns(state) ->list[int]:
    """
    Mixes the columns of the state.
    """

    for i in range(4):

        c = i * 4 
        
        # Save the original column values
        b0 = state[c]
        b1 = state[c+1]
        b2 = state[c+2]
        b3 = state[c+3]
        
        # Apply the equations of the fixed MixColumns matrix
        state[c]   = g_mul(0x02, b0) ^ g_mul(0x03, b1) ^ b2 ^ b3
        state[c+1] = b0 ^ g_mul(0x02, b1) ^ g_mul(0x03, b2) ^ b3
        state[c+2] = b0 ^ b1 ^ g_mul(0x02, b2) ^ g_mul(0x03, b3)
        state[c+3] = g_mul(0x03, b0) ^ b1 ^ b2 ^ g_mul(0x02, b3)
        
    return state

    