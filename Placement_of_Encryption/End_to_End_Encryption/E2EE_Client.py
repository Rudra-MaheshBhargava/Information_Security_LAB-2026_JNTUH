
# ============================================================
# END-TO-END ENCRYPTION - CLIENT
# RSA-OAEP + AES-256-GCM
# TCP CLIENT-SERVER COMMUNICATION
# ============================================================

import socket
import json
import base64
import os

from cryptography.hazmat.primitives.asymmetric import padding
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
            raise ConnectionError("Server disconnected.")

        data += chunk

    return json.loads(data.decode("utf-8"))


# Encrypt message
def encrypt_message(message, public_key):

    # Generate AES-256 key
    aes_key = AESGCM.generate_key(bit_length=256)

    # Generate 96-bit nonce
    nonce = os.urandom(12)

    # Encrypt message using AES-GCM
    aes_cipher = AESGCM(aes_key)

    ciphertext = aes_cipher.encrypt(
        nonce,
        message.encode("utf-8"),
        None
    )

    # Encrypt AES key using server's RSA public key
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_key, nonce, ciphertext


# MAIN CLIENT PROGRAM

print("==========================================")
print("       E2EE CLIENT")
print("==========================================")

try:

    # Connect to server
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    client.connect((HOST, PORT))

    print("\nConnected to E2EE Server.")

    # Receive server public key
    received_data = receive_data(client)

    public_key_pem = base64.b64decode(
        received_data["public_key"]
    )

    public_key = serialization.load_pem_public_key(
        public_key_pem
    )

    print("Server public key received successfully.")

    # Enter message
    message = input("\nEnter message to send: ")

    # Encrypt message
    encrypted_key, nonce, ciphertext = encrypt_message(
        message,
        public_key
    )

    print("\n========== ENCRYPTED DATA ==========")

    print("Encrypted AES Key:", encrypted_key.hex())
    print("Nonce:", nonce.hex())
    print("Ciphertext:", ciphertext.hex())

    # Prepare encrypted data
    data = {
        "encrypted_key": base64.b64encode(
            encrypted_key
        ).decode("utf-8"),

        "nonce": base64.b64encode(
            nonce
        ).decode("utf-8"),

        "ciphertext": base64.b64encode(
            ciphertext
        ).decode("utf-8")
    }

    # Send encrypted data to server
    client.sendall(
        (json.dumps(data) + "\n").encode("utf-8")
    )

    print("\nEncrypted message sent to server.")

    # Receive server response
    response = receive_data(client)

    print("\n========== SERVER RESPONSE ==========")

    print("Status:", response["status"])
    print("Message:", response["message"])

    client.close()

except ConnectionRefusedError:

    print("\nError: Server is not running.")
    print("Start E2EE_Server.py first.")

except Exception as error:

    print("\nClient Error:", error)

finally:

    try:
        client.close()
    except NameError:
        pass
