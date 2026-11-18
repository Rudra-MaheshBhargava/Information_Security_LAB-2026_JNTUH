
import socket
import json
import hashlib

# DSA public parameters (educational values only)
p = 23
q = 11
g = 4

# Client's public key
y = 2

HOST = "127.0.0.1"
PORT = 5004


def verify_signature(message, r, s):
    if not (0 < r < q and 0 < s < q):
        return False

    try:
        # Step 1: Calculate hash
        message_hash = int.from_bytes(
            hashlib.sha256(message.encode()).digest(), "big"
        ) % q

        # Step 2: Calculate w
        w = pow(s, -1, q)

        # Step 3: Calculate u1 and u2
        u1 = (message_hash * w) % q
        u2 = (r * w) % q

        # Step 4: Calculate v
        value = (pow(g, u1, p) * pow(y, u2, p)) % p
        v = value % q

        # Step 5: Verify signature
        return v == r

    except ValueError:
        return False


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind((HOST, PORT))
server.listen(1)

print("===================================")
print("       DSA SERVER")
print("===================================")
print(f"Server listening on {HOST}:{PORT}")
print("Waiting for Client...\n")

connection, address = server.accept()

with connection:
    print("Client connected:", address)

    data = connection.recv(4096).decode()

    try:
        received = json.loads(data)

        message = received["message"]
        r = int(received["r"])
        s = int(received["s"])

        print("\nReceived Message:", message)
        print("Received Signature:")
        print("r =", r)
        print("s =", s)

        print("\nVerifying digital signature...")

        if verify_signature(message, r, s):
            print("Signature Status: VALID")
            print("Message is authentic and unchanged.")
            result = "VALID"
        else:
            print("Signature Status: INVALID")
            print("Message may have been modified.")
            result = "INVALID"

        connection.sendall(result.encode())

    except (KeyError, ValueError, json.JSONDecodeError):
        print("Invalid data received.")
        connection.sendall(b"INVALID")

server.close()
