
import socket
import json
import base64
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


HOST = "127.0.0.1"
PORT = 5001

TICKET_LIFETIME = 300
CLOCK_SKEW = 60

# Same secret key used by AS
TGS_SECRET_KEY = bytes.fromhex(
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

# Secret key shared between TGS and Service Server
SERVICE_SECRET_KEY = bytes.fromhex(
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

replay_cache = set()


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


def generate_service_ticket(request):

    print("\n[TGS] Service ticket request received.")

    # Step 1: Decrypt TGT using TGS secret key
    tgt_data = decrypt_data(
        TGS_SECRET_KEY,
        request["tgt"]
    )

    username = tgt_data["username"]

    if time.time() > tgt_data["expires"]:
        raise ValueError("TGT expired.")

    client_tgs_key = base64.b64decode(
        tgt_data["session_key"]
    )

    # Step 2: Decrypt Client authenticator
    authenticator = decrypt_data(
        client_tgs_key,
        request["authenticator"]
    )

    if authenticator["username"] != username:
        raise ValueError("Client identity mismatch.")

    timestamp = authenticator["timestamp"]

    if abs(time.time() - timestamp) > CLOCK_SKEW:
        raise ValueError("Invalid authenticator timestamp.")

    # Step 3: Check replay attack
    replay_id = (
        username,
        authenticator["authenticator_id"]
    )

    if replay_id in replay_cache:
        raise ValueError("Replay attack detected.")

    replay_cache.add(replay_id)

    print("[TGS] TGT verified.")
    print("[TGS] Client authenticator verified.")

    # Step 4: Generate Client-Service session key
    client_service_key = AESGCM.generate_key(
        bit_length=256
    )

    # Step 5: Create Service Ticket
    service_ticket_data = {
        "username": username,
        "session_key": base64.b64encode(
            client_service_key
        ).decode(),
        "expires": time.time() + TICKET_LIFETIME
    }

    service_ticket = encrypt_data(
        SERVICE_SECRET_KEY,
        service_ticket_data
    )

    # Step 6: Prepare response for Client
    response_data = {
        "session_key": base64.b64encode(
            client_service_key
        ).decode(),
        "service_ticket": service_ticket
    }

    encrypted_response = encrypt_data(
        client_tgs_key,
        response_data
    )

    print("[TGS] Service Ticket generated.")
    print("[TGS] Service Ticket sent to Client.")

    return encrypted_response


def main():

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))
    server.listen(5)

    print("========== TICKET GRANTING SERVER ==========")
    print("[TGS] Running on port", PORT)

    while True:

        connection, address = server.accept()

        with connection:

            try:

                request = receive_data(connection)

                response = generate_service_ticket(request)

                send_data(connection, response)

            except Exception as error:

                print("[TGS] Error:", error)
                send_data(connection, {"error": str(error)})


if __name__ == "__main__":
    main()
