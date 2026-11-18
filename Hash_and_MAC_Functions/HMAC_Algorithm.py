
# ============================================================
# HMAC ALGORITHM
# Hash-Based Message Authentication Code
# Using SHA-256
# From Scratch - No External Libraries
# ============================================================

import hashlib


# 1. HMAC GENERATION
def generate_hmac(message, secret_key):

    block_size = 64

    # Convert key and message into bytes
    key = secret_key.encode("utf-8")
    message = message.encode("utf-8")

    # If key is longer than block size, hash it
    if len(key) > block_size:

        key = hashlib.sha256(key).digest()

    # Pad key to block size
    key = key.ljust(block_size, b'\x00')

    # Inner and outer padding
    ipad = bytes([0x36] * block_size)
    opad = bytes([0x5C] * block_size)

    # Inner hash
    inner_key = bytes(a ^ b for a, b in zip(key, ipad))

    inner_hash = hashlib.sha256(
        inner_key + message
    ).digest()

    # Outer hash
    outer_key = bytes(a ^ b for a, b in zip(key, opad))

    hmac_result = hashlib.sha256(
        outer_key + inner_hash
    ).hexdigest()

    return hmac_result


# 2. HMAC VERIFICATION
def verify_hmac(message, secret_key, received_hmac):

    calculated_hmac = generate_hmac(message, secret_key)

    return calculated_hmac == received_hmac


# 3. MAIN PROGRAM

print("==========================================")
print("          HMAC ALGORITHM")
print("==========================================")

# Input message and secret key
message = input("\nEnter message: ")

secret_key = input("Enter secret key: ")

# Generate HMAC
generated_hmac = generate_hmac(message, secret_key)

print("\n========== HMAC OUTPUT ==========")

print("Original Message:", message)

print("Secret Key:", secret_key)

print("Generated HMAC:")
print(generated_hmac)

# Verify HMAC
received_hmac = input("\nEnter HMAC for verification: ")

if verify_hmac(message, secret_key, received_hmac):

    print("\nHMAC Verification: SUCCESS")
    print("Message Integrity: VERIFIED")
    print("Message Authentication: SUCCESS")

else:

    print("\nHMAC Verification: FAILED")
    print("Message may have been modified or key is incorrect.")
