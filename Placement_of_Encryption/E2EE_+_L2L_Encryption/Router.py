import socket
import json
import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "127.0.0.1"
PORT = 5001

NEXT_HOST = "127.0.0.1"
NEXT_PORT = 5002

# Client-to-Router shared key
INCOMING_KEY = bytes.fromhex(
    "22222222222222222222222222222222"
    "22222222222222222222222222222222"
)

# Router-to-Server shared key
OUTGOING_KEY = bytes.fromhex(
    "11111111111111111111111111111111"
    "11111111111111111111111111111111"
)


def receive_message(connection):
    data = b""

    while not data.endswith(b"\n"):
        chunk = connection.recv(4096)

        if not chunk:
            break

        data += chunk

    return json.loads(data.decode())


def decrypt_link_layer(data):

    nonce = base64.b64decode(data["nonce"])
    ciphertext = base64.b64decode(data["ciphertext"])

    aes = AESGCM(INCOMING_KEY)

    return aes.decrypt(
        nonce,
        ciphertext,
        b"CLIENT-TO-ROUTER"
    )


def encrypt_link_layer(data):

    aes = AESGCM(OUTGOING_KEY)

    nonce = os.urandom(12)

    ciphertext = aes.encrypt(
        nonce,
        data,
        b"ROUTER-TO-SERVER"
    )

    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }


def main():

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))
    server.listen(1)

    print("[ROUTER] Waiting for Client...")

    connection, address = server.accept()

    with connection:

        print("[ROUTER] Client connected.")

        # Step 1: Remove Client-to-Router encryption
        received_data = receive_message(connection)

        e2ee_payload = decrypt_link_layer(received_data)

        print("[ROUTER] First link encryption removed.")

        # Step 2: Apply Router-to-Server encryption
        encrypted_data = encrypt_link_layer(e2ee_payload)

        print("[ROUTER] Second link encryption applied.")

        # Step 3: Forward data to Server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:

            client.connect((NEXT_HOST, NEXT_PORT))

            client.sendall(
                json.dumps(encrypted_data).encode() + b"\n"
            )

        print("[ROUTER] Encrypted data forwarded to Server.")

    server.close()


if __name__ == "__main__":
    main()