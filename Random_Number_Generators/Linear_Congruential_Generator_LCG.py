
# ============================================================
# LINEAR CONGRUENTIAL GENERATOR (LCG)
# ============================================================


def lcg_generator(seed, multiplier, increment, modulus, count):

    random_numbers = []

    current = seed

    for i in range(count):

        # Generate next pseudo-random number
        current = (multiplier * current + increment) % modulus

        random_numbers.append(current)

    return random_numbers


# MAIN PROGRAM

print("==========================================")
print("   LINEAR CONGRUENTIAL GENERATOR (LCG)")
print("==========================================")

try:

    seed = int(input("Enter initial seed: "))
    multiplier = int(input("Enter multiplier (a): "))
    increment = int(input("Enter increment (c): "))
    modulus = int(input("Enter modulus (m): "))
    count = int(input("Enter number of random numbers: "))

    # Validate inputs
    if seed < 0:
        raise ValueError("Seed must be non-negative.")

    if multiplier <= 0:
        raise ValueError("Multiplier must be positive.")

    if increment < 0:
        raise ValueError("Increment must be non-negative.")

    if modulus <= 1:
        raise ValueError("Modulus must be greater than 1.")

    if seed >= modulus:
        raise ValueError("Seed must be smaller than modulus.")

    if count <= 0:
        raise ValueError("Count must be greater than zero.")

    # Generate pseudo-random numbers
    random_numbers = lcg_generator(
        seed, multiplier, increment, modulus, count
    )

    # Display output
    print("\n========== LCG OUTPUT ==========")

    for i, number in enumerate(random_numbers, start=1):

        print(f"Random Number {i}: {number}")

    print("\nLCG generation completed successfully!")

except ValueError as e:

    print("Input Error:", e)
