
# ============================================================
# SHA-512 HASH FUNCTION
# Using Python Built-in hashlib
# No External Libraries
# ============================================================

import hashlib


# 1. GENERATE SHA-512 HASH
def generate_hash(message):

    sha512 = hashlib.sha512()

    sha512.update(message.encode("utf-8"))

    return sha512.hexdigest()


# 2. MAIN PROGRAM

print("==========================================")
print("          SHA-512 HASH FUNCTION")
print("==========================================")

# Get input message
message = input("\nEnter message: ")

# Generate hash
hash_value = generate_hash(message)

# Display output
print("\n========== SHA-512 OUTPUT ==========")

print("Original Message:", message)

print("SHA-512 Hash:")
print(hash_value)

print("\nHash Length:", len(hash_value), "Hexadecimal Characters")

print("Digest Size:", hashlib.sha512().digest_size, "Bytes")

print("\nSHA-512 Hash Generated Successfully!")
