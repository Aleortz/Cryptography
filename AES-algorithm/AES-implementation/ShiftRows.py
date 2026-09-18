def shift_rows(state):
    """
    Perfoms a cyclic left shift on the rows of the state.
    'state' is a list of 16 integers.
    """
    
    # Rows 0: Don't shift the first row (row 0)
    # state[0], state[4], state[8], state[12] remain unchanged
    
    # Rows 1: Cyclic left shift by 1 position
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
    
    # Rows 2: Cyclic left shift by 2 positions 
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    
    # Rows 3: Cyclic left shift by 3 positions to the left
    state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]
    
    return state