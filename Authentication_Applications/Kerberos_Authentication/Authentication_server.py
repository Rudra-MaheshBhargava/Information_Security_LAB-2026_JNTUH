
import socket
import json
import base64
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


HOST = "127.0.0.1"
PORT = 5000

TICKET_LIFETIME = 300
SALT = b"Kerberos_Lab_Salt_2026"

# Secret key shared between AS and TGS
TGS_SECRET_KEY = bytes.fromhex(
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)


def derive_client_key(password):

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=200000
    )

    return kdf.derive(password.encode())


def encrypt_data(key, data):

    aes = AESGCM(key)
    nonce = AESGCM.generate_key(bit_length=128)[:12]

    ciphertext = aes.encrypt(
        nonce,
        json.dumps(data).encode(),
        None
    )

    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }


def receive_data(connection):

    data = b""

    while not data.endswith(b"\n"):
        chunk = connection.recv(4096)

        if not chunk:
            raise ConnectionError("Client disconnected.")

        data += chunk

    return json.loads(data.decode())


def send_data(connection, data):

    connection.sendall(
        json.dumps(data).encode() + b"\n"
    )


def authenticate_client(request):

    username = request["username"]

    print(f"\n[AS] Authentication request received from {username}.")

    # Demonstration user database
    user_database = {
        "student": derive_client_key("password123")
    }

    if username not in user_database:
        raise ValueError("Invalid username.")

    client_secret_key = user_database[username]

    # Generate Client-TGS session key
    client_tgs_key = AESGCM.generate_key(bit_length=256)

    # Create Ticket Granting Ticket
    tgt_data = {
        "username": username,
        "session_key": base64.b64encode(
            client_tgs_key
        ).decode(),
        "expires": time.time() + TICKET_LIFETIME
    }

    # Encrypt TGT using AS-TGS shared key
    tgt = encrypt_data(TGS_SECRET_KEY, tgt_data)

    # Create response for Client
    response_data = {
        "session_key": base64.b64encode(
            client_tgs_key
        ).decode(),
        "tgt": tgt
    }

    # Encrypt response using Client's secret key
    encrypted_response = encrypt_data(
        client_secret_key,
        response_data
    )

    print("[AS] Client authenticated.")
    print("[AS] TGT generated successfully.")

    return encrypted_response


def main():

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))
    server.listen(5)

    print("========== AUTHENTICATION SERVER ==========")
    print("[AS] Running on port", PORT)

    while True:

        connection, address = server.accept()

        with connection:

            try:
                request = receive_data(connection)

                response = authenticate_client(request)

                send_data(connection, response)

                print("[AS] TGT sent to Client.")

            except Exception as error:

                print("[AS] Error:", error)
                send_data(connection, {"error": str(error)})


if __name__ == "__main__":
    main()
