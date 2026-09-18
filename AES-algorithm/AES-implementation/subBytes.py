'S-box for AES SubBytes transformation. This is a 16x16 matrix'


def sub_bytes(state, s_box) -> list[int]:
    """
    Substitutes each byte in the state with its corresponding value from the S-box.
    """
    for i in range(len(state)):
        state[i] = s_box[state[i]]
    return state