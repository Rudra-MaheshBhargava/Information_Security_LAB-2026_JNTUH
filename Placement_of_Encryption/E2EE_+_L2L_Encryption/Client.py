import socket
import json
import base64
import os

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "127.0.0.1"
PORT = 5001

# Client-to-Router shared key
LINK_KEY = bytes.fromhex(
    "22222222222222222222222222222222"
    "22222222222222222222222222222222"
)


def encrypt_e2ee(message, server_public_key):

    # Generate AES-256 key
    aes_key = AESGCM.generate_key(bit_length=256)

    nonce = os.urandom(12)

    # Encrypt original message
    aes = AESGCM(aes_key)

    ciphertext = aes.encrypt(
        nonce,
        message.encode(),
        None
    )

    # Encrypt AES key using Server's RSA public key
    encrypted_key = server_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }


def encrypt_link_layer(data):

    aes = AESGCM(LINK_KEY)

    nonce = os.urandom(12)

    ciphertext = aes.encrypt(
        nonce,
        data,
        b"CLIENT-TO-ROUTER"
    )

    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }


def main():

    # Load Server public key
    with open("server_public.pem", "rb") as file:

        server_public_key = serialization.load_pem_public_key(
            file.read()
        )

    print("[CLIENT] Server public key loaded.")

    message = input("\nEnter message: ")

    # Step 1: Apply End-to-End Encryption
    e2ee_payload = encrypt_e2ee(
        message,
        server_public_key
    )

    print("\n[CLIENT] E2EE encryption completed.")
    print("[CLIENT] AES-256-GCM encryption applied.")
    print("[CLIENT] RSA-OAEP key encryption completed.")

    # Convert E2EE payload into bytes
    e2ee_data = json.dumps(e2ee_payload).encode()

    # Step 2: Apply Link-to-Link Encryption
    link_payload = encrypt_link_layer(e2ee_data)

    print("[CLIENT] L2L encryption completed.")

    # Step 3: Send encrypted message to Router
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:

        client.connect((HOST, PORT))

        client.sendall(
            json.dumps(link_payload).encode() + b"\n"
        )

    print("[CLIENT] Encrypted message sent successfully.")


if __name__ == "__main__":
    main()