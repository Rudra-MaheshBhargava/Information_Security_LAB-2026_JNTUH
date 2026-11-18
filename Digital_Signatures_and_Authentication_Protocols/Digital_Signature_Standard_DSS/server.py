
import socket

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature

HOST = "127.0.0.1"
PORT = 5005


def receive_exact(connection, size):
    data = b""

    while len(data) < size:
        chunk = connection.recv(size - len(data))

        if not chunk:
            raise ConnectionError("Client disconnected unexpectedly.")

        data += chunk

    return data


def receive_data(connection):
    # Receive public key length
    key_length = int.from_bytes(receive_exact(connection, 4), "big")

    # Receive complete public key
    public_key_data = receive_exact(connection, key_length)

    # Load public key
    public_key = load_pem_public_key(public_key_data)

    # Receive message length
    message_length = int.from_bytes(receive_exact(connection, 4), "big")

    # Receive message
    message = receive_exact(connection, message_length)

    # Receive signature length
    signature_length = int.from_bytes(receive_exact(connection, 4), "big")

    # Receive signature
    signature = receive_exact(connection, signature_length)

    return public_key, message, signature


def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message,
            hashes.SHA256()
        )
        return True

    except InvalidSignature:
        return False


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind((HOST, PORT))
server.listen(1)

print("===================================")
print("          DSS SERVER")
print("===================================")
print(f"Server listening on {HOST}:{PORT}")
print("Waiting for Client...\n")

try:
    connection, address = server.accept()

    with connection:
        print("Client connected:", address)

        public_key, message, signature = receive_data(connection)

        print("\nReceived Public Key Successfully")
        print("Received Message:", message.decode())
        print("Digital Signature received.")

        print("\nVerifying Digital Signature...")

        if verify_signature(public_key, message, signature):
            print("Signature Status: VALID")
            print("Message integrity verified.")
            result = "VALID"

        else:
            print("Signature Status: INVALID")
            print("Message integrity verification failed.")
            result = "INVALID"

        connection.sendall(result.encode())

except (ConnectionError, ValueError, OSError) as error:
    print("Communication Error:", error)

finally:
    server.close()
