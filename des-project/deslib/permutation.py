def permute(value: int, table: tuple[int, ...], input_width: int) -> int:
    """Permute the bits of a value according to a given table.

    Args:
        value (int): The integer value to permute.
        table (tuple[int, ...]): A tuple representing the permutation table.
        input_width (int): The width of the input value in bits.

    Returns:
        int: The permuted integer value.
    """
    if value >= (1 << input_width):
        raise ValueError(f"Value must be less than {1 << input_width} for input width {input_width}")
    permuted_value = 0
    for i, position in enumerate(table):
        # Extract the bit at the specified position and set it in the new position
        bit = (value >> (position - 1)) & 1
        permuted_value |= (bit << i)
    return permuted_value