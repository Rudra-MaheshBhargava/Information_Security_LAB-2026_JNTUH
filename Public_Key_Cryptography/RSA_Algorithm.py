
# ============================================================
# RSA ALGORITHM
# Encryption and Decryption
# From Scratch - No External Libraries
# ============================================================

import math


# 1. CHECK PRIME NUMBER
def is_prime(number):

    if number < 2:
        return False

    for i in range(2, math.isqrt(number) + 1):

        if number % i == 0:
            return False

    return True


# 2. GENERATE RSA KEYS
def generate_keys(p, q):

    if not is_prime(p) or not is_prime(q):
        raise ValueError("Both numbers must be prime.")

    if p == q:
        raise ValueError("Prime numbers must be different.")

    n = p * q

    phi = (p - 1) * (q - 1)

    # Automatically select a valid public exponent
    e = 65537

    if e >= phi or math.gcd(e, phi) != 1:

        e = 3

        while e < phi and math.gcd(e, phi) != 1:
            e += 2

        if e >= phi:
            raise ValueError("Unable to find a valid public exponent.")

    # Calculate private exponent
    d = pow(e, -1, phi)

    public_key = (e, n)

    private_key = (d, n)

    return public_key, private_key


# 3. ENCRYPTION
def encrypt(message, public_key):

    e, n = public_key

    ciphertext = []

    for character in message:

        m = ord(character)

        if m >= n:
            raise ValueError("Character value exceeds RSA modulus.")

        c = pow(m, e, n)

        ciphertext.append(c)

    return ciphertext


# 4. DECRYPTION
def decrypt(ciphertext, private_key):

    d, n = private_key

    plaintext = ""

    for value in ciphertext:

        m = pow(value, d, n)

        plaintext += chr(m)

    return plaintext


# 5. MAIN PROGRAM
print("==========================================")
print("             RSA ALGORITHM")
print("==========================================")

try:

    p = int(input("Enter first prime number (p): "))
    q = int(input("Enter second prime number (q): "))

    # Generate RSA keys
    public_key, private_key = generate_keys(p, q)

    print("\n========== KEY GENERATION ==========")

    print("Prime Number p:", p)
    print("Prime Number q:", q)

    print("Modulus (n):", p * q)
    print("Euler Totient:", (p - 1) * (q - 1))

    print("Public Key:", public_key)
    print("Private Key:", private_key)

    # Input message
    message = input("\nEnter plaintext message: ")

    # Encryption
    ciphertext = encrypt(message, public_key)

    print("\n========== ENCRYPTION ==========")

    print("Encrypted Message:", ciphertext)

    # Decryption
    plaintext = decrypt(ciphertext, private_key)

    print("\n========== DECRYPTION ==========")

    print("Decrypted Message:", plaintext)

    print("\nRSA Encryption and Decryption Completed Successfully!")

except ValueError as error:

    print("\nError:", error)
