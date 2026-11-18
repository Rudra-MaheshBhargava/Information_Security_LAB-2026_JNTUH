
import socket
import json
import base64
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


HOST = "127.0.0.1"
PORT = 5002

CLOCK_SKEW = 60

# Same secret key used by TGS
SERVICE_SECRET_KEY = bytes.fromhex(
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

replay_cache = set()


def encrypt_data(key, data):

    import os

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

    print("\n[SERVICE SERVER] Authentication request received.")

    # Step 1: Decrypt Service Ticket
    ticket_data = decrypt_data(
        SERVICE_SECRET_KEY,
        request["service_ticket"]
    )

    username = ticket_data["username"]

    if time.time() > ticket_data["expires"]:
        raise ValueError("Service Ticket expired.")

    client_service_key = base64.b64decode(
        ticket_data["session_key"]
    )

    # Step 2: Decrypt Client authenticator
    authenticator = decrypt_data(
        client_service_key,
        request["authenticator"]
    )

    if authenticator["username"] != username:
        raise ValueError("Client identity mismatch.")

    timestamp = authenticator["timestamp"]

    if abs(time.time() - timestamp) > CLOCK_SKEW:
        raise ValueError("Invalid authenticator timestamp.")

    # Step 3: Prevent replay attacks
    replay_id = (
        username,
        authenticator["authenticator_id"]
    )

    if replay_id in replay_cache:
        raise ValueError("Replay attack detected.")

    replay_cache.add(replay_id)

    print("[SERVICE SERVER] Service Ticket verified.")
    print("[SERVICE SERVER] Authenticator verified.")

    # Step 4: Create mutual authentication response
    response_data = {
        "status": "ACCESS GRANTED",
        "username": username,
        "timestamp": timestamp + 1
    }

    encrypted_response = encrypt_data(
        client_service_key,
        response_data
    )

    print("[SERVICE SERVER] Client authenticated.")

    return encrypted_response


def main():

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))
    server.listen(5)

    print("========== SERVICE SERVER ==========")
    print("[SERVICE SERVER] Running on port", PORT)

    while True:

        connection, address = server.accept()

        with connection:

            try:

                request = receive_data(connection)

                response = authenticate_client(request)

                send_data(connection, response)

                print("[SERVICE SERVER] Access granted.")

            except Exception as error:

                print("[SERVICE SERVER] Error:", error)
                send_data(connection, {"error": str(error)})


if __name__ == "__main__":
    main()
