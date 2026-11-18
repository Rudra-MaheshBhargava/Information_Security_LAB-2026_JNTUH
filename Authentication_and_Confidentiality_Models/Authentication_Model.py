
# ============================================================
# AUTHENTICATION MODEL USING RSA DIGITAL SIGNATURE
# From Scratch - No External Libraries
# ============================================================

import math
import hashlib


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


# Generate SHA-256 hash
def generate_hash(message):

    return int.from_bytes(
        hashlib.sha256(message.encode()).digest(),
        byteorder="big"
    )


# Sign message using private key
def sign_message(message, private_key):

    d, n = private_key

    message_hash = generate_hash(message)

    # Educational raw RSA signature demonstration
    signature = pow(message_hash % n, d, n)

    return signature


# Verify signature using public key
def verify_signature(message, signature, public_key):

    e, n = public_key

    message_hash = generate_hash(message)

    verified_hash = pow(signature, e, n)

    return verified_hash == message_hash % n


# MAIN PROGRAM

print("==========================================")
print("       RSA AUTHENTICATION MODEL")
print("==========================================")

public_key, private_key = generate_keys()

print("\nRSA Keys Generated Successfully!")

message = input("\nEnter message from sender: ")

# Sender signs message
signature = sign_message(message, private_key)

print("\nDigital Signature:")
print(signature)

# Receiver verifies message
print("\n========== RECEIVER SIDE ==========")

received_message = input("Enter received message: ")

if verify_signature(received_message, signature, public_key):

    print("\nSignature Verification: SUCCESS")
    print("Sender Authentication: SUCCESS")
    print("Message Integrity: VERIFIED")

else:

    print("\nSignature Verification: FAILED")
    print("Message may have been modified.")
