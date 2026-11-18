
import struct
from decimal import Decimal, getcontext
from math import ceil, log10

# ============================================================
# 1. GENERATE BLOWFISH INITIAL CONSTANTS FROM PI
# ============================================================

def generate_constants():

    total_digits = 8336

    # Set arbitrary precision
    precision = ceil(total_digits * log10(16)) + 50
    getcontext().prec = precision

    # Chudnovsky algorithm for calculating Pi
    M = 1
    L = 13591409
    X = 1
    K = 6

    pi_sum = Decimal(L)

    terms = ceil(precision / 14.181647) + 1

    for i in range(1, terms):

        M = (M * (K * K * K - 16 * K)) // (i ** 3)
        L += 545140134
        X *= -262537412640768000

        pi_sum += Decimal(M * L) / Decimal(X)

        K += 12

    pi = (Decimal(426880) * Decimal(10005).sqrt()) / pi_sum

    # Extract hexadecimal fractional digits of Pi
    fractional = pi - 3

    hex_digits = []

    for _ in range(total_digits):

        fractional *= 16
        digit = int(fractional)

        hex_digits.append(format(digit, 'x'))

        fractional -= digit

    hex_string = ''.join(hex_digits)

    # Convert hexadecimal digits into 32-bit integers
    values = [
        int(hex_string[i:i+8], 16)
        for i in range(0, total_digits, 8)
    ]

    P = values[:18]

    S = [
        values[18:274],
        values[274:530],
        values[530:786],
        values[786:1042]
    ]

    return P, S


# ============================================================
# 2. BLOWFISH CLASS
# ============================================================

class Blowfish:

    def __init__(self, key): # the self parameter is used to refer to the instance of the class being created. It allows access to the attributes and methods of the class within its own methods.

        if not isinstance(key, str): # here the str is a built-in Python class that represents a string data type. The isinstance() function checks if the key variable is an instance of the str class. If key is not a string, it raises a ValueError with the message "Key must be a string". This ensures that the key provided to the Blowfish class is of the correct type before proceeding with further operations.
            raise ValueError("Key must be a string")

        key = key.encode('utf-8') # The line key = key.encode('utf-8') converts the string key into a bytes object using UTF-8 encoding. This is necessary because the Blowfish algorithm operates on binary data, and the key needs to be in a byte format for further processing.

        if not 4 <= len(key) <= 56:
            raise ValueError("Key must be between 4 and 56 bytes")

        self.P, self.S = generate_constants()

        # Key expansion
        j = 0

        for i in range(18):

            data = 0

            for _ in range(4):

                data = (data << 8) | key[j]

                j = (j + 1) % len(key)

            self.P[i] ^= data

        left = 0
        right = 0

        # Update P-array
        for i in range(0, 18, 2):

            left, right = self.encrypt_block(left, right)

            self.P[i] = left
            self.P[i + 1] = right

        # Update S-boxes
        for box in self.S:

            for i in range(0, 256, 2):

                left, right = self.encrypt_block(left, right)

                box[i] = left
                box[i + 1] = right

    # ========================================================
    # 3. F FUNCTION
    # ========================================================

    def F(self, x):

        a = (x >> 24) & 0xFF
        b = (x >> 16) & 0xFF
        c = (x >> 8) & 0xFF
        d = x & 0xFF

        result = (self.S[0][a] + self.S[1][b]) & 0xFFFFFFFF

        result ^= self.S[2][c]

        result = (result + self.S[3][d]) & 0xFFFFFFFF

        return result

    # ========================================================
    # 4. ENCRYPTION OF ONE 64-BIT BLOCK
    # ========================================================

    def encrypt_block(self, left, right):

        for i in range(16):

            left ^= self.P[i]

            right ^= self.F(left)

            left, right = right, left

        left, right = right, left

        right ^= self.P[16]

        left ^= self.P[17]

        return left & 0xFFFFFFFF, right & 0xFFFFFFFF

    # ========================================================
    # 5. DECRYPTION OF ONE 64-BIT BLOCK
    # ========================================================

    def decrypt_block(self, left, right):

        for i in range(17, 1, -1):

            left ^= self.P[i]

            right ^= self.F(left)

            left, right = right, left

        left, right = right, left

        right ^= self.P[1]

        left ^= self.P[0]

        return left & 0xFFFFFFFF, right & 0xFFFFFFFF

    # ========================================================
    # 6. ENCRYPT PLAINTEXT
    # ========================================================

    def encrypt(self, plaintext):

        data = plaintext.encode('utf-8')

        # PKCS-style padding
        padding = 8 - (len(data) % 8)

        data += bytes([padding]) * padding

        encrypted = b''

        for i in range(0, len(data), 8):

            left, right = struct.unpack(
                '>II', data[i:i+8]
            )

            left, right = self.encrypt_block(left, right)

            encrypted += struct.pack('>II', left, right)

        return encrypted.hex()

    # ========================================================
    # 7. DECRYPT CIPHERTEXT
    # ========================================================

    def decrypt(self, ciphertext):

        data = bytes.fromhex(ciphertext)

        if not data or len(data) % 8 != 0:

            raise ValueError("Invalid ciphertext")

        decrypted = b''

        for i in range(0, len(data), 8):

            left, right = struct.unpack(
                '>II', data[i:i+8]
            )

            left, right = self.decrypt_block(left, right)

            decrypted += struct.pack('>II', left, right)

        # Remove padding
        padding = decrypted[-1]

        if not 1 <= padding <= 8:

            raise ValueError("Invalid padding")

        if decrypted[-padding:] != bytes([padding]) * padding:

            raise ValueError("Invalid padding")

        return decrypted[:-padding].decode('utf-8')


# ============================================================
# 8. MAIN PROGRAM
# ============================================================

print("===================================")
print("       BLOWFISH ALGORITHM")
print("===================================")

key = input("Enter Secret Key: ")

plaintext = input("Enter Plaintext: ")

try:

    bf = Blowfish(key)

    print("\nGenerating Blowfish key schedule...")

    encrypted = bf.encrypt(plaintext)

    print("\n========== ENCRYPTION ==========")

    print("Original Text :", plaintext)

    print("Secret Key    :", key)

    print("Encrypted Text:", encrypted)

    decrypted = bf.decrypt(encrypted)

    print("\n========== DECRYPTION ==========")

    print("Decrypted Text:", decrypted)

    if decrypted == plaintext:

        print("\nResult: Encryption and Decryption Successful!")

    else:

        print("\nResult: Verification Failed!")

except Exception as e:

    print("\nError:", e)
