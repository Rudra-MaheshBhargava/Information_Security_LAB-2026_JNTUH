
# ============================================================
# BASIC PSEUDO-RANDOM NUMBER GENERATOR (PRNG)
# ============================================================


# 1. PRNG FUNCTION

def generate_random_numbers(seed, count):

    numbers = []

    current = seed

    for i in range(count):

        current = (current * 1103515245 + 12345) % (2 ** 31)

        numbers.append(current)

    return numbers


# 2. MAIN PROGRAM

print("======================================")
print("   PSEUDO-RANDOM NUMBER GENERATOR")
print("======================================")

try:

    seed = int(input("Enter initial seed: "))

    count = int(input("Enter number of random numbers: "))

    if seed < 0:
        raise ValueError("Seed must be non-negative.")

    if count <= 0:
        raise ValueError("Count must be greater than zero.")

    # Generate random numbers
    random_numbers = generate_random_numbers(seed, count)

    # Display results
    print("\n========== PRNG OUTPUT ==========")

    for i, number in enumerate(random_numbers):

        print("Random Number", i + 1, ":", number)

    print("\nPRNG generation completed successfully!")

except ValueError as e:

    print("Error:", e)
