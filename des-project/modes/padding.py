def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    """Apply PKCS#7 padding to the input data.

    Args:
        data (bytes): The input data to be padded.
        block_size (int): The block size in bytes (default is 8 for DES).

    Returns:
        bytes: The padded data.
    """
    padding_length: int = block_size - (len(data) % block_size)
    padding: bytes = bytes([padding_length] * padding_length)
    return data + padding

def pkcs7_unpad(padded_data: bytes, block_size: int = 8) -> bytes:
    """Remove PKCS#7 padding from the input data.

    Args:
        padded_data (bytes): The padded data to be unpadded.
        block_size (int): The block size in bytes (default is 8 for DES).

    Returns:
        bytes: The original unpadded data.

    Raises:
        ValueError: If the padding is invalid.
    """
    if not padded_data:
        raise ValueError("Input data is empty")

    padding_length: int = padded_data[-1]
    if padding_length < 1 or padding_length > 8:
        raise ValueError("Invalid padding length")

    if padded_data[-padding_length:] != bytes([padding_length] * padding_length):
        raise ValueError("Invalid padding bytes")

    return padded_data[:-padding_length]
