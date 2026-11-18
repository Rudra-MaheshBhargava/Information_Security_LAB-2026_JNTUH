
# ============================================================
# COMBINED CONFIDENTIALITY AND AUTHENTICATION
# RSA + SHA-256
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
        hashlib.sha256(message).digest(),
        byteorder="big"
    )


# Sign message
def sign_message(message, private_key):

    d, n = private_key

    message_hash = generate_hash(message)

    signature = pow(message_hash % n, d, n)

    return signature


# Encrypt message and signature
def encrypt_data(message, signature, public_key):

    e, n = public_key

    data = message + "|" + str(signature)

    encrypted_data = []

    for char in data:

        value = ord(char)

        if value >= n:
            raise ValueError("Character exceeds RSA modulus")

        encrypted_data.append(pow(value, e, n))

    return encrypted_data


# Decrypt received data
def decrypt_data(encrypted_data, private_key):

    d, n = private_key

    decrypted_data = ""

    for value in encrypted_data:

        decrypted_value = pow(value, d, n)

        decrypted_data += chr(decrypted_value)

    return decrypted_data


# Verify digital signature
def verify_signature(message, signature, public_key):

    e, n = public_key

    message_hash = generate_hash(message)

    verified_hash = pow(signature, e, n)

    return verified_hash == message_hash % n


# MAIN PROGRAM

print("================================================")
print(" COMBINED CONFIDENTIALITY AND AUTHENTICATION")
print("================================================")

# Generate sender keys
sender_public, sender_private = generate_keys()

# Generate receiver keys
receiver_public, receiver_private = generate_keys()

print("\nSender and Receiver RSA keys generated.")

# Sender enters message
message = input("\nEnter message from sender: ")

# Step 1: Generate digital signature
signature = sign_message(message.encode(), sender_private)

print("\nDigital Signature Generated Successfully!")

# Step 2: Encrypt message and signature
encrypted_data = encrypt_data(
    message, signature, receiver_public
)

print("\n========== ENCRYPTED DATA ==========")
print(encrypted_data)

print("\nEncrypted data sent to receiver.")

# Step 3: Receiver decrypts data
decrypted_data = decrypt_data(
    encrypted_data, receiver_private
)

# Separate message and signature
received_message, received_signature = decrypted_data.rsplit("|", 1)

received_signature = int(received_signature)

print("\n========== RECEIVER SIDE ==========")

print("Decrypted Message:", received_message)

# Step 4: Verify signature
if verify_signature(
    received_message.encode(),
    received_signature,
    sender_public
):

    print("\nSignature Verification: SUCCESS")
    print("Confidentiality: SUCCESS")
    print("Authentication: SUCCESS")
    print("Message Integrity: VERIFIED")

else:

    print("\nSignature Verification: FAILED")
    print("Message may have been modified.")
