
# ============================================================
# CONFIDENTIALITY MODEL USING RSA
# From Scratch - No External Libraries
# ============================================================

import math
import secrets


# Check whether a number is prime
def is_prime(n):

    if n < 2:
        return False

    for i in range(2, math.isqrt(n) + 1):

        if n % i == 0:
            return False

    return True


# Generate RSA keys
def generate_keys():

    p = 1009
    q = 1013

    n = p * q

    phi = (p - 1) * (q - 1)

    e = 65537

    if math.gcd(e, phi) != 1:
        raise ValueError("Invalid RSA parameters")

    d = pow(e, -1, phi)

    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key


# Encrypt message
def encrypt(message, public_key):

    e, n = public_key

    encrypted = []

    for char in message:

        m = ord(char)

        if m >= n:
            raise ValueError("Character value exceeds RSA modulus")

        c = pow(m, e, n)

        encrypted.append(c)

    return encrypted


# Decrypt message
def decrypt(ciphertext, private_key):

    d, n = private_key

    decrypted = ""

    for c in ciphertext:

        m = pow(c, d, n)

        decrypted += chr(m)

    return decrypted


# MAIN PROGRAM

print("==========================================")
print("       RSA CONFIDENTIALITY MODEL")
print("==========================================")

public_key, private_key = generate_keys()

print("\nRSA Keys Generated Successfully!")

message = input("\nEnter message from sender: ")

# Sender encrypts
ciphertext = encrypt(message, public_key)

print("\nEncrypted Message:")
print(ciphertext)

# Receiver decrypts
plaintext = decrypt(ciphertext, private_key)

print("\n========== RECEIVER SIDE ==========")

print("Decrypted Message:", plaintext)

print("\nConfidentiality Demonstrated Successfully!")
