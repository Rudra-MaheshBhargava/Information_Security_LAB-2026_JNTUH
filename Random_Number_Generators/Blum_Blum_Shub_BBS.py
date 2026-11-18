
# ============================================================
# BLUM BLUM SHUB (BBS) PSEUDO-RANDOM NUMBER GENERATOR
# ============================================================

from math import gcd


def is_prime(number):

    if number < 2:
        return False

    for i in range(2, int(number ** 0.5) + 1):
        if number % i == 0:
            return False

    return True


def validate_blum_prime(number):

    if not is_prime(number):
        return False

    return number % 4 == 3


def bbs_generator(p, q, seed, count):

    # Calculate modulus
    n = p * q

    # Initialize seed
    x = (seed * seed) % n

    random_bits = []
    random_numbers = []

    for i in range(count):

        # Generate next state
        x = (x * x) % n

        # Extract least significant bit
        bit = x % 2

        random_bits.append(bit)
        random_numbers.append(x)

    return n, random_numbers, random_bits


# MAIN PROGRAM

print("==========================================")
print("      BLUM BLUM SHUB (BBS) GENERATOR")
print("==========================================")

try:

    p = int(input("Enter first prime number (p): "))
    q = int(input("Enter second prime number (q): "))
    seed = int(input("Enter initial seed: "))
    count = int(input("Enter number of random bits: "))

    # Validate prime numbers
    if not validate_blum_prime(p):
        raise ValueError("p must be a prime number congruent to 3 modulo 4.")

    if not validate_blum_prime(q):
        raise ValueError("q must be a prime number congruent to 3 modulo 4.")

    if p == q:
        raise ValueError("p and q must be distinct prime numbers.")

    n = p * q

    # Validate seed
    if seed <= 1 or seed >= n:
        raise ValueError("Seed must be greater than 1 and less than n.")

    if gcd(seed, n) != 1:
        raise ValueError("Seed must be relatively prime to n.")

    if count <= 0:
        raise ValueError("Number of bits must be greater than zero.")

    # Generate random bits
    n, numbers, bits = bbs_generator(p, q, seed, count)

    # Display output
    print("\n========== BBS OUTPUT ==========")

    print("Modulus (n):", n)

    print("\nGenerated Numbers:")

    for i, number in enumerate(numbers, start=1):
        print(f"X{i} = {number}")

    print("\nGenerated Random Bits:")
    print("".join(map(str, bits)))

    print("\nBBS generation completed successfully!")

except ValueError as e:

    print("Input Error:", e)
