
# ============================================================
# NEEDHAM-SCHROEDER CLIENT
# ============================================================

import socket
import secrets
import json

from common import (
    HOST, KDC_PORT, SERVER_PORT,
    KEY_CLIENT,
    encrypt, decrypt,
    send_data, receive_data
)


print("==========================================")
print("          CLIENT APPLICATION")
print("==========================================")

client_name = "Client"
server_name = "Server"


# STEP 1: Request session key from KDC

nonce_client = secrets.token_hex(8)

request = {
    "client": client_name,
    "server": server_name,
    "nonce_client": nonce_client
}

print("\n========== STEP 1 ==========")
print("Connecting to KDC...")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:

    connection.connect((HOST, KDC_PORT))

    print("Connected to KDC.")

    send_data(connection, request)

    # STEP 2: Receive KDC response
    encrypted_response = receive_data(connection)

    response_data = decrypt(
        encrypted_response, KEY_CLIENT
    )

    response = json.loads(response_data.decode())

    if response["nonce_client"] != nonce_client:
        raise ValueError("KDC nonce verification failed!")

    if response["server"] != server_name:
        raise ValueError("Unexpected server identity!")

    session_key = response["session_key"]
    encrypted_ticket = response["ticket"]

    print("\n========== STEP 2 ==========")
    print("KDC response received.")
    print("Nonce verification: SUCCESS")
    print("Session key received.")


# STEP 3: Forward server ticket
print("\n========== STEP 3 ==========")
print("Connecting to Server...")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:

    connection.connect((HOST, SERVER_PORT))

    print("Connected to Server.")

    send_data(connection, encrypted_ticket)

    print("Encrypted ticket forwarded to Server.")

    # STEP 4: Receive server challenge
    encrypted_challenge = receive_data(connection)

    challenge_data = decrypt(
        encrypted_challenge, session_key
    )

    challenge = json.loads(challenge_data.decode())

    nonce_server = challenge["nonce_server"]

    print("\n========== STEP 4 ==========")
    print("Server challenge received.")
    print("Challenge decrypted successfully.")

    # STEP 5: Send challenge response
    response = {
        "response": nonce_server - 1
    }

    encrypted_response = encrypt(
        json.dumps(response).encode(),
        session_key
    )

    send_data(connection, encrypted_response)

    print("\n========== STEP 5 ==========")
    print("Challenge response sent to Server.")

    print("\nClient completed the protocol exchange.")
