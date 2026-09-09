"""Implementation of S-boxes for the DES algorithm."""


def sbox_lookup(s_box: list[list[int]], six_bits: int) -> int:
    """Perform an S-box lookup for a given input value.

    Args:
        s_box (list[list[int]]): The S-box to use for the lookup.
        input_value (int): The 6-bit input value to look up in the S-box.

    Returns:
        int: The 4-bit output value from the S-box.
    """
    # Extract the row and column from the input value
    row = ((six_bits & 0b100000) >> 4) | (six_bits & 0b000001)
    column = (six_bits & 0b011110) >> 1

    # Perform the lookup in the S-box
    return s_box[row][column]
