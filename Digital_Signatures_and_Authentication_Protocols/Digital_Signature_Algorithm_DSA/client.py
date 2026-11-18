
import socket
import json
import hashlib
import secrets

# DSA public parameters (educational values only)
p = 23
q = 11
g = 4

# Client's private key
x = 6

# Generate public key
y = pow(g, x, p)

HOST = "127.0.0.1"
PORT = 5004


def generate_signature(message):
    # Step 1: Calculate message hash
    message_hash = int.from_bytes(
        hashlib.sha256(message.encode()).digest(), "big"
    ) % q

    # Step 2: Generate a random nonce k
    while True:
        k = secrets.randbelow(q - 1) + 1

        # Step 3: Calculate r
        r = pow(g, k, p) % q

        if r == 0:
            continue

        # Step 4: Calculate s
        k_inverse = pow(k, -1, q)
        s = (k_inverse * (message_hash + x * r)) % q

        if s != 0:
            break

    return r, s


print("===================================")
print("       DSA CLIENT")
print("===================================")

print("Private Key:", x)
print("Public Key:", y)

message = input("\nEnter message to sign: ")

# Generate digital signature
r, s = generate_signature(message)

print("\nGenerated Digital Signature:")
print("r =", r)
print("s =", s)

# Prepare data
data = {
    "message": message,
    "r": r,
    "s": s
}

# Connect to Server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    client.connect((HOST, PORT))

    client.sendall(json.dumps(data).encode())

    result = client.recv(1024).decode()

    print("\nServer Verification Result:", result)

except ConnectionRefusedError:
    print("Connection failed. Start the Server first.")

finally:
    client.close()
