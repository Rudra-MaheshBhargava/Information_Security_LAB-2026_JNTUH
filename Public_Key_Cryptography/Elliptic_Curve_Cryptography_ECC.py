
# ============================================================
# ELLIPTIC CURVE CRYPTOGRAPHY (ECC)
# User-Defined Curve Parameters
# From Scratch - No External Libraries
# ============================================================

# 1. MODULAR INVERSE
def mod_inverse(value, modulus):

    return pow(value % modulus, -1, modulus)


# 2. CHECK PRIME NUMBER
def is_prime(n):

    if n < 2:
        return False

    for i in range(2, int(n ** 0.5) + 1):

        if n % i == 0:
            return False

    return True


# 3. CHECK WHETHER POINT LIES ON CURVE
def is_on_curve(point, a, b, p):

    if point is None:
        return True

    x, y = point

    left = (y * y) % p

    right = (x**3 + a*x + b) % p

    return left == right


# 4. POINT ADDITION
def point_add(P, Q, a, p):

    if P is None:
        return Q

    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    if x1 == x2 and (y1 + y2) % p == 0:
        return None

    if P == Q:

        numerator = (3*x1*x1 + a) % p

        denominator = (2*y1) % p

    else:

        numerator = (y2 - y1) % p

        denominator = (x2 - x1) % p

    slope = (
        numerator * mod_inverse(denominator, p)
    ) % p

    x3 = (slope*slope - x1 - x2) % p

    y3 = (slope*(x1 - x3) - y1) % p

    return (x3, y3)


# 5. SCALAR MULTIPLICATION
def scalar_multiply(k, point, a, p):

    result = None

    current = point

    while k > 0:

        if k % 2 == 1:

            result = point_add(result, current, a, p)

        current = point_add(current, current, a, p)

        k //= 2

    return result


# 6. MAIN PROGRAM

print("==========================================")
print("   ELLIPTIC CURVE CRYPTOGRAPHY (ECC)")
print("==========================================")

try:

    # Get curve parameters from user
    p = int(input("Enter prime number (p): "))

    a = int(input("Enter coefficient (a): "))

    b = int(input("Enter coefficient (b): "))

    if not is_prime(p):
        raise ValueError("p must be a prime number.")

    a %= p
    b %= p

    # Check non-singular curve
    if (4*a**3 + 27*b**2) % p == 0:
        raise ValueError("Invalid curve: singular elliptic curve.")

    print("\nCurve Equation:")
    print(f"y^2 = x^3 + {a}x + {b} (mod {p})")

    # Get generator point
    gx = int(input("\nEnter generator point X coordinate: "))

    gy = int(input("Enter generator point Y coordinate: "))

    G = (gx, gy)

    if not (0 <= gx < p and 0 <= gy < p):
        raise ValueError("Generator coordinates must be in the range 0 to p-1.")

    if not is_on_curve(G, a, b, p):
        raise ValueError("Generator point does not lie on the curve.")

    print("\nGenerator Point:", G)

    # Get private key
    private_key = int(input("\nEnter private key: "))

    if private_key <= 0:
        raise ValueError("Private key must be positive.")

    # Generate public key
    public_key = scalar_multiply(
        private_key, G, a, p
    )

    if public_key is None:
        raise ValueError("Invalid private key or generator point.")

    print("\n========== ECC KEY GENERATION ==========")

    print("Private Key:", private_key)

    print("Public Key:", public_key)

    print("\nPublic Key Verification:")

    if is_on_curve(public_key, a, b, p):

        print("SUCCESS - Public key lies on the curve.")

    else:

        print("FAILED")

    print("\nECC Key Generation Completed Successfully!")

except (ValueError, ZeroDivisionError) as error:

    print("\nInput Error:", error)
