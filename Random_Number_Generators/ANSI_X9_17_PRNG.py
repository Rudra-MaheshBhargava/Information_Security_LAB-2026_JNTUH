
# ============================================================
# ANSI X9.17 PSEUDO-RANDOM NUMBER GENERATOR
# Using DES Encryption
# ============================================================

from Crypto.Cipher import DES


def xor_bytes(a, b):
    """Perform XOR operation on two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))


def ansi_x917_prng(key, seed, dt, count):

    # Create DES cipher
    cipher = DES.new(key, DES.MODE_ECB)

    # Initial seed
    V = seed

    random_numbers = []

    for i in range(count):

        # Step 1: Encrypt Date-Time Vector
        I = cipher.encrypt(dt)

        # Step 2: Generate pseudo-random value
        R = cipher.encrypt(xor_bytes(I, V))

        # Step 3: Update seed
        V = cipher.encrypt(xor_bytes(R, I))

        random_numbers.append(R)

    return random_numbers


# MAIN PROGRAM

print("==========================================")
print("    ANSI X9.17 PSEUDO-RANDOM GENERATOR")
print("==========================================")

try:

    key_input = input("Enter 64-bit DES key (16 hex characters): ")
    seed_input = input("Enter initial seed (16 hex characters): ")
    dt_input = input("Enter date-time vector (16 hex characters): ")

    count = int(input("Enter number of random values: "))

    # Convert hexadecimal inputs into bytes
    key = bytes.fromhex(key_input)
    seed = bytes.fromhex(seed_input)
    dt = bytes.fromhex(dt_input)

    # Validate inputs
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes.")

    if len(seed) != 8:
        raise ValueError("Seed must be exactly 8 bytes.")

    if len(dt) != 8:
        raise ValueError("Date-Time Vector must be exactly 8 bytes.")

    if count <= 0:
        raise ValueError("Number of values must be greater than zero.")

    # Generate random values
    results = ansi_x917_prng(key, seed, dt, count)

    # Display results
    print("\n========== GENERATED VALUES ==========")

    for i, value in enumerate(results, start=1):
        print(f"Random Number {i}: {value.hex().upper()}")

    print("\nANSI X9.17 generation completed!")

except ValueError as e:
    print("Input Error:", e)

except Exception as e:
    print("Error:", e)
