def permute(value: int, table: tuple[int, ...], input_width: int) -> int:
    """Permute the bits of a value according to a given table.

    Args:
        value (int): The integer value to permute.
        table (tuple[int, ...]): A tuple representing the permutation table.

    Returns:
        int: The permuted integer value.
    """
    permuted_value = 0
    for i, position in enumerate(table):
        # Extract the bit at the specified position and set it in the new position
        bit = (value >> (position - 1)) & 1
        permuted_value |= (bit << i)
    return permuted_value