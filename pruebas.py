master_key = "Clave123"
def text_to_binary(plaintext: str) -> str:
    binary_result = ""
    for char in plaintext:
        binary_result += format(ord(char), '08b')
    return binary_result

example_plaintext = text_to_binary(master_key)
print(f"length of binary string: {len(example_plaintext)}")