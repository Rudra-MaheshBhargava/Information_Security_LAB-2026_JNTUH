
# ============================================================
# END-TO-END ENCRYPTION - SERVER
# RSA-OAEP + AES-256-GCM
# TCP CLIENT-SERVER COMMUNICATION
# ============================================================

import socket
import json
import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


HOST = "127.0.0.1"
PORT = 5000


# Receive one JSON message
def receive_data(connection):

    data = b""

    while not data.endswith(b"\n"):

        chunk = connection.recv(4096)

        if not chunk:
            raise ConnectionError("Client disconnected.")

        data += chunk

    return json.loads(data.decode("utf-8"))


# Generate RSA key pair
def generate_keys():

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    return public_key, private_key


# Send server public key to client
def send_public_key(connection, public_key):

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    public_key_encoded = base64.b64encode(
        public_pem
    ).decode("utf-8")

    data = {
        "public_key": public_key_encoded
    }

    connection.sendall(
        (json.dumps(data) + "\n").encode("utf-8")
    )


# Decrypt received message
def decrypt_message(data, private_key):

    encrypted_key = base64.b64decode(
        data["encrypted_key"]
    )

    nonce = base64.b64decode(
        data["nonce"]
    )

    ciphertext = base64.b64decode(
        data["ciphertext"]
    )

    # Decrypt AES key using RSA private key
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt message using AES-GCM
    aes_cipher = AESGCM(aes_key)

    plaintext = aes_cipher.decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext.decode("utf-8")


# MAIN SERVER PROGRAM

print("==========================================")
print("       E2EE SERVER")
print("==========================================")

# Generate server keys
public_key, private_key = generate_keys()

print("\nRSA Key Pair Generated Successfully!")

# Start TCP server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind((HOST, PORT))

server.listen(5)

print(f"\nServer listening on {HOST}:{PORT}")
print("Waiting for client connection...")

try:

    while True:

        connection, address = server.accept()

        with connection:

            print("\nClient connected:", address)

            try:

                # Send public key to client
                send_public_key(connection, public_key)

                print("Server public key sent to client.")

                # Receive encrypted data
                received_data = receive_data(connection)

                print("\nEncrypted data received successfully.")

                # Decrypt message
                message = decrypt_message(
                    received_data,
                    private_key
                )

                print("\n========== DECRYPTED MESSAGE ==========")

                print("Original Message:", message)

                print("\nMessage decrypted successfully!")

                response = {
                    "status": "success",
                    "message": "Message received and decrypted successfully."
                }

            except Exception as error:

                print("\nDecryption failed:", error)

                response = {
                    "status": "error",
                    "message": "Message decryption failed."
                }

            # Send response to client
            connection.sendall(
                (json.dumps(response) + "\n").encode("utf-8")
            )

except KeyboardInterrupt:

    print("\nServer shutting down...")

finally:

    server.close()
