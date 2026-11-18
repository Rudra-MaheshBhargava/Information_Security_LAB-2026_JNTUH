

def xor(a, b):
    return a ^ b


def generate_keys(key, rounds):
    """Generate round keys from the main key.""" 
    keys = []
    for i in range(rounds): # here the loop iterates through the number of rounds specified by the user, generating a unique round key for each round. the i variable represents the current round number, starting from 0 up to rounds-1.
        keys.append((key + i) % 256) # Generate a simple round key by adding the round number to the main key and taking modulo 256, why 256 is because we are working with bytes (0-255), how does it works meaning that the key will wrap around if it exceeds 255, ensuring that all keys are valid byte values. are we converting the key to bytes? no, we are not converting the key to bytes, we are just generating integer values that will be used as round keys in the Feistel cipher. these integer values will later be used in the encryption and decryption processes, where they will be combined with the data being processed.
    return keys


def feistel_encrypt(plaintext, key, rounds):
    data = plaintext.encode() # Convert plaintext to bytes

    # Padding if data length is odd
    if len(data) % 2 != 0:
        data += b'\x00' # Pad with null byte

    half = len(data) // 2
    left = int.from_bytes(data[:half], 'big') # Convert left half to integer and the 'big' argument specifies big-endian byte order
    right = int.from_bytes(data[half:], 'big') # Convert right half to integer and the 'big' argument specifies big-endian byte order

    round_keys = generate_keys(key, rounds) # Generate round keys from the main key

    for round_key in round_keys: # Iterate through each round key to perform the Feistel rounds
        new_left = right # The new left half is assigned the value of the current right half, effectively swapping the halves for the next round.
        new_right = left ^ (right ^ round_key) # The new right half is computed by XORing the current left half with the result of XORing the current right half and the round key. This operation introduces non-linearity and diffusion into the cipher, making it more secure. The XOR operation is a fundamental part of the Feistel structure, as it combines the data with the round key in a reversible manner.
        left, right = new_left, new_right

    ciphertext = left.to_bytes(half, 'big') + right.to_bytes(half, 'big') # Convert the final left and right halves back to bytes and concatenate them to form the complete ciphertext. The 'big' argument specifies big-endian byte order, ensuring that the byte representation is consistent with the original data format.

    # return ciphertext.hex() # Return the ciphertext as a hexadecimal string, which is a common format for representing binary data in a human-readable way. The .hex() method converts the byte sequence into a string of hexadecimal characters, making it easier to display and transmit. 

    #if you want to show the cipher text in the text format then you can use the following code
    #return ciphertext.decode('latin-1') # Return the ciphertext as a string using 'latin-1' encoding, which allows for a direct mapping of byte values to characters. This can be useful for displaying the ciphertext in a text format, but it may not be suitable for all applications
    
    # the 'latin-1' encoding is used here to ensure that all byte values (0-255) can be represented as characters, avoiding potential issues with character encoding that could arise with other encodings like UTF-8. This approach allows for a straightforward conversion of the ciphertext bytes into a string format that can be easily displayed or transmitted, while still preserving the original byte values for decryption.
    return ciphertext.decode('latin-1')

def feistel_decrypt(ciphertext, key, rounds):
    # data = bytes.fromhex(ciphertext) # Convert the hexadecimal string back to bytes, reversing the encoding process used during encryption. The bytes.fromhex() method takes a string of hexadecimal characters and converts it into a corresponding byte sequence, allowing for the original binary data to be reconstructed for decryption.

    #when the ciphertext is in the text format then we can use the following code
    #data = ciphertext.encode('latin-1') # Convert the string back to bytes using 'latin-1' encoding, which allows for a direct mapping of characters to byte values. This can be useful for reconstructing the original byte sequence from a text representation of the ciphertext, enabling the decryption process to proceed correctly.
    data = ciphertext.encode('latin-1')

    half = len(data) // 2
    left = int.from_bytes(data[:half], 'big')
    right = int.from_bytes(data[half:], 'big')

    round_keys = generate_keys(key, rounds)

    for round_key in reversed(round_keys):
        new_right = left # The new right half is assigned the value of the current left half, effectively swapping the halves for the next round.
        new_left = right ^ (left ^ round_key) # The new left half is computed by XORing the current right half with the result of XORing the current left half and the round key. This operation introduces non-linearity and diffusion into the cipher, making it more secure. The XOR operation is a fundamental part of the Feistel structure, as it combines the data with the round key in a reversible manner.
        left, right = new_left, new_right

    plaintext = left.to_bytes(half, 'big') + right.to_bytes(half, 'big')

    return plaintext.rstrip(b'\x00').decode()


# Main program
key = int(input("Enter key (0-255): "))
plaintext = input("Enter plaintext: ")

rounds = int(input("Enter number of rounds: "))

encrypted = feistel_encrypt(plaintext, key, rounds)
print("\nEncrypted Ciphertext:", encrypted)

decrypted = feistel_decrypt(encrypted, key, rounds)
print("Decrypted Plaintext:", decrypted)
