
import socket
import json
import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "127.0.0.1"
PORT = 5002

# Shared key for Router-to-Server link
LINK_KEY = bytes.fromhex(
    "11111111111111111111111111111111"
    "11111111111111111111111111111111"
)


def receive_message(connection):
    data = b""

    while not data.endswith(b"\n"):
        chunk = connection.recv(4096)

        if not chunk:
            raise ConnectionError("Connection closed unexpectedly.")

        data += chunk

    return json.loads(data.decode("utf-8"))


def decrypt_link_layer(data):

    nonce = base64.b64decode(data["nonce"])
    ciphertext = base64.b64decode(data["ciphertext"])

    aes = AESGCM(LINK_KEY)

    decrypted_data = aes.decrypt(
        nonce,
        ciphertext,
        b"ROUTER-TO-SERVER"
    )

    return decrypted_data


def main():

    # Step 1: Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    # Step 2: Save Server public key for Client
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("server_public.pem", "wb") as file:
        file.write(public_pem)

    print("[SERVER] RSA key pair generated.")
    print("[SERVER] Public key saved as server_public.pem")

    # Step 3: Start TCP Server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server.bind((HOST, PORT))
    server.listen(1)

    print("[SERVER] Waiting for Router...")

    try:

        connection, address = server.accept()

        with connection:

            print("\n[SERVER] Router connected.")

            # Step 4: Receive encrypted data from Router
            received_data = receive_message(connection)

            # Step 5: Decrypt Link-to-Link encryption
            decrypted_data = decrypt_link_layer(received_data)

            print("[SERVER] Link-to-Link decryption completed.")

            # FIX: Convert decrypted bytes into a Python dictionary
            e2ee_payload = json.loads(
                decrypted_data.decode("utf-8")
            )

            # Step 6: Extract E2EE components
            encrypted_key = base64.b64decode(
                e2ee_payload["encrypted_key"]
            )

            nonce = base64.b64decode(
                e2ee_payload["nonce"]
            )

            ciphertext = base64.b64decode(
                e2ee_payload["ciphertext"]
            )

            # Step 7: Decrypt AES key using RSA private key
            aes_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(
                        algorithm=hashes.SHA256()
                    ),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            print("[SERVER] E2EE AES key decrypted using RSA.")

            # Step 8: Decrypt original message using AES-256-GCM
            aes = AESGCM(aes_key)

            plaintext = aes.decrypt(
                nonce,
                ciphertext,
                None
            )

            print("[SERVER] End-to-End decryption completed.")

            # Step 9: Display original message
            print("\n========== SERVER MESSAGE ==========")
            print("Decrypted Message:", plaintext.decode("utf-8"))
            print("====================================")

    except Exception as error:

        print("[SERVER] Error:", error)

    finally:

        server.close()


if __name__ == "__main__":
    main()
