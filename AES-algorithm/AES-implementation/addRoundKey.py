def add_round_key(state, round_key):
    """
    Combine the state with the round key using XOR.
    Both are 1D lists of 16 integers.
    """
    for i in range(16):
        state[i] ^= round_key[i]
    return state