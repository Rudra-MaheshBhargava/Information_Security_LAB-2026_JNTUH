
# ============================================================
# TRUE RANDOM NUMBER GENERATOR (TRNG)
# OS-backed cryptographically secure random generation
# ============================================================

import secrets


# ============================================================
# 1. GENERATE RANDOM BITS
# ============================================================

def generate_random_bits(number_of_bits):

    random_number = secrets.randbits(number_of_bits)

    binary_number = format(random_number, f'0{number_of_bits}b')

    return binary_number


# ============================================================
# 2. GENERATE RANDOM INTEGER
# ============================================================

def generate_random_number(minimum, maximum):

    return secrets.randbelow(maximum - minimum + 1) + minimum


# ============================================================
# 3. GENERATE RANDOM BYTE VALUES
# ============================================================

def generate_random_bytes(number_of_bytes):

    random_data = secrets.token_bytes(number_of_bytes)

    return random_data


# ============================================================
# 4. GENERATE RANDOM HEXADECIMAL VALUE
# ============================================================

def generate_random_hex(number_of_bytes):

    random_hex = secrets.token_hex(number_of_bytes)

    return random_hex


# ============================================================
# 5. MAIN PROGRAM
# ============================================================

print("==============================================")
print("       TRUE RANDOM NUMBER GENERATOR")
print("==============================================")

print("\nSelect an option:")

print("1. Generate Random Bits")
print("2. Generate Random Integer")
print("3. Generate Random Bytes")
print("4. Generate Random Hexadecimal Number")

choice = input("\nEnter your choice: ").strip()


# ============================================================
# OPTION 1: RANDOM BITS
# ============================================================

if choice == '1':

    try:

        bits = int(input("Enter number of bits: "))

        if bits <= 0:
            raise ValueError("Number of bits must be positive.")

        random_bits = generate_random_bits(bits)

        print("\n========== RANDOM BITS ==========")

        print("Random Binary Number:", random_bits)

        print("Number of Bits:", len(random_bits))

    except ValueError as e:

        print("Error:", e)


# ============================================================
# OPTION 2: RANDOM INTEGER
# ============================================================

elif choice == '2':

    try:

        minimum = int(input("Enter minimum value: "))

        maximum = int(input("Enter maximum value: "))

        if minimum > maximum:
            raise ValueError("Minimum cannot exceed maximum.")

        random_number = generate_random_number(minimum, maximum)

        print("\n========== RANDOM INTEGER ==========")

        print("Generated Random Number:", random_number)

    except ValueError as e:

        print("Error:", e)


# ============================================================
# OPTION 3: RANDOM BYTES
# ============================================================

elif choice == '3':

    try:

        number_of_bytes = int(input("Enter number of bytes: "))

        if number_of_bytes <= 0:
            raise ValueError("Number of bytes must be positive.")

        random_data = generate_random_bytes(number_of_bytes)

        print("\n========== RANDOM BYTES ==========")

        print("Random Bytes:", random_data)

        print("Hexadecimal:", random_data.hex())

        print("Number of Bytes:", len(random_data))

    except ValueError as e:

        print("Error:", e)


# ============================================================
# OPTION 4: RANDOM HEXADECIMAL
# ============================================================

elif choice == '4':

    try:

        number_of_bytes = int(input("Enter number of bytes: "))

        if number_of_bytes <= 0:
            raise ValueError("Number of bytes must be positive.")

        random_hex = generate_random_hex(number_of_bytes)

        print("\n========== RANDOM HEXADECIMAL ==========")

        print("Random Hexadecimal Number:", random_hex)

        print("Number of Bytes:", number_of_bytes)

    except ValueError as e:

        print("Error:", e)


# ============================================================
# INVALID OPTION
# ============================================================

else:

    print("\nInvalid choice. Please select 1, 2, 3 or 4.")


print("\n==============================================")
print("             PROGRAM COMPLETED")
print("==============================================")
