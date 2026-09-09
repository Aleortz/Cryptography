def int_to_des_key(effective_key_56_bit: int) -> bytes:
    """
    Convert a 56-bit integer into a 64-bit DES key (8 bytes).
    Automatically calculates and appends the odd parity bit for each byte.
    """
    key_bytes = bytearray()
    
    # Process 8 blocks of 7 bits
    for i in range(7, -1, -1):
        # Extract 7 bits from the 56-bit integer
        seven_bits = (effective_key_56_bit >> (i * 7)) & 0x7F
        
        # Calculate the number of '1's in the 7 bits
        ones_count = bin(seven_bits).count('1')
        
        # Determine odd parity bit: 
        # If the count of '1's is even, we need a '1' to make it odd.
        # If the count is odd, we append a '0'.
        parity_bit = 1 if ones_count % 2 == 0 else 0
        
        # Shift the 7 bits left and append the parity bit
        final_byte = (seven_bits << 1) | parity_bit
        key_bytes.append(final_byte)
        
    return bytes(key_bytes)