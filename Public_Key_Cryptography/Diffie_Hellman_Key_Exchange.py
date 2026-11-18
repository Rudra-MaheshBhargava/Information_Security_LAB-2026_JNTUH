
# ============================================================
# DIFFIE-HELLMAN KEY EXCHANGE ALGORITHM
# From Scratch - No External Libraries
# ============================================================


# 1. GENERATE PUBLIC KEY
def generate_public_key(g, private_key, p):

    public_key = pow(g, private_key, p)

    return public_key


# 2. GENERATE SHARED SECRET KEY
def generate_shared_secret(received_key, private_key, p):

    shared_secret = pow(received_key, private_key, p)

    return shared_secret


# 3. MAIN PROGRAM

print("==========================================")
print("     DIFFIE-HELLMAN KEY EXCHANGE")
print("==========================================")

try:

    # Public parameters
    p = int(input("Enter prime number (p): "))
    g = int(input("Enter generator (g): "))

    # Private keys
    alice_private = int(input("Enter Alice's private key: "))
    bob_private = int(input("Enter Bob's private key: "))

    # Validate inputs
    if p <= 2:
        raise ValueError("Prime number must be greater than 2.")

    if alice_private <= 0 or bob_private <= 0:
        raise ValueError("Private keys must be positive.")

    if not (1 < g < p):
        raise ValueError("Generator must be between 1 and p.")

    if not (1 < alice_private < p):
        raise ValueError("Alice's private key must be between 1 and p.")

    if not (1 < bob_private < p):
        raise ValueError("Bob's private key must be between 1 and p.")

    # Alice generates public key
    alice_public = generate_public_key(
        g, alice_private, p
    )

    # Bob generates public key
    bob_public = generate_public_key(
        g, bob_private, p
    )

    print("\n========== PUBLIC KEY EXCHANGE ==========")

    print("Alice's Public Key:", alice_public)
    print("Bob's Public Key:", bob_public)

    # Alice calculates shared secret
    alice_secret = generate_shared_secret(
        bob_public, alice_private, p
    )

    # Bob calculates shared secret
    bob_secret = generate_shared_secret(
        alice_public, bob_private, p
    )

    print("\n========== SHARED SECRET ==========")

    print("Alice's Shared Secret:", alice_secret)
    print("Bob's Shared Secret:", bob_secret)

    # Verify shared secret
    if alice_secret == bob_secret:

        print("\nShared Secret Key Established Successfully!")

    else:

        print("\nShared Secret Key Generation Failed!")

except ValueError as error:

    print("\nInput Error:", error)
