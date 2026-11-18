
import socket
import json
import base64
import os
import time
import getpass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


HOST = "127.0.0.1"

AS_PORT = 5000
TGS_PORT = 5001
SERVICE_PORT = 5002

SALT = b"Kerberos_Lab_Salt_2026"


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
    nonce = os.urandom(12)

    ciphertext = aes.encrypt(
        nonce,
        json.dumps(data).encode(),
        None
    )

    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }


def decrypt_data(key, encrypted_data):

    nonce = base64.b64decode(encrypted_data["nonce"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])

    aes = AESGCM(key)

    plaintext = aes.decrypt(nonce, ciphertext, None)

    return json.loads(plaintext.decode())


def communicate(port, request):

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:

        client.connect((HOST, port))

        client.sendall(
            json.dumps(request).encode() + b"\n"
        )

        data = b""

        while not data.endswith(b"\n"):
            chunk = client.recv(4096)

            if not chunk:
                raise ConnectionError("Server disconnected.")

            data += chunk

    response = json.loads(data.decode())

    if "error" in response:
        raise ValueError(response["error"])

    return response


def main():

    print("======================================")
    print("       KERBEROS CLIENT")
    print("======================================")

    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")

    client_key = derive_client_key(password)

    try:

        # ======================================
        # STEP 1: AUTHENTICATION SERVER
        # ======================================

        print("\n========== STEP 1: AS AUTHENTICATION ==========")

        as_request = {
            "username": username
        }

        as_response = communicate(
            AS_PORT,
            as_request
        )

        # Decrypt AS response using Client secret key
        as_data = decrypt_data(
            client_key,
            as_response
        )

        client_tgs_key = base64.b64decode(
            as_data["session_key"]
        )

        tgt = as_data["tgt"]

        print("[CLIENT] Authentication successful.")
        print("[CLIENT] Ticket Granting Ticket received.")

        # ======================================
        # STEP 2: TICKET GRANTING SERVER
        # ======================================

        print("\n========== STEP 2: TGS AUTHENTICATION ==========")

        authenticator_tgs = {
            "username": username,
            "timestamp": time.time(),
            "authenticator_id": base64.b64encode(
                os.urandom(16)
            ).decode()
        }

        encrypted_authenticator_tgs = encrypt_data(
            client_tgs_key,
            authenticator_tgs
        )

        tgs_request = {
            "tgt": tgt,
            "authenticator": encrypted_authenticator_tgs
        }

        tgs_response = communicate(
            TGS_PORT,
            tgs_request
        )

        # Decrypt TGS response using Client-TGS session key
        tgs_data = decrypt_data(
            client_tgs_key,
            tgs_response
        )

        client_service_key = base64.b64decode(
            tgs_data["session_key"]
        )

        service_ticket = tgs_data["service_ticket"]

        print("[CLIENT] TGT verified by TGS.")
        print("[CLIENT] Service Ticket received.")

        # ======================================
        # STEP 3: SERVICE SERVER
        # ======================================

        print("\n========== STEP 3: SERVICE AUTHENTICATION ==========")

        service_timestamp = time.time()

        authenticator_service = {
            "username": username,
            "timestamp": service_timestamp,
            "authenticator_id": base64.b64encode(
                os.urandom(16)
            ).decode()
        }

        encrypted_authenticator_service = encrypt_data(
            client_service_key,
            authenticator_service
        )

        service_request = {
            "service_ticket": service_ticket,
            "authenticator": encrypted_authenticator_service
        }

        service_response = communicate(
            SERVICE_PORT,
            service_request
        )

        # Decrypt Server response
        service_data = decrypt_data(
            client_service_key,
            service_response
        )

        # Verify mutual authentication
        if (
            service_data["username"] == username
            and service_data["timestamp"] == service_timestamp + 1
            and service_data["status"] == "ACCESS GRANTED"
        ):

            print("[CLIENT] Service Server authenticated.")
            print("[CLIENT] Mutual authentication successful.")
            print("\n========== AUTHENTICATION SUCCESSFUL ==========")
            print("Username:", username)
            print("Status: ACCESS GRANTED")

        else:

            print("[CLIENT] Server verification failed.")

    except Exception as error:

        print("\n[CLIENT] Authentication failed:", error)


if __name__ == "__main__":
    main()
