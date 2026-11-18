
# ============================================================
# NEEDHAM-SCHROEDER SERVER
# ============================================================

import socket
import json
import secrets

from common import (
    HOST, SERVER_PORT,
    KEY_SERVER,
    encrypt, decrypt,
    send_data, receive_data
)


print("==========================================")
print("          SERVER STARTED")
print("==========================================")

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.setsockopt(
    socket.SOL_SOCKET,
    socket.SO_REUSEADDR,
    1
)

server.bind((HOST, SERVER_PORT))
server.listen(1)

print(f"Server listening on {HOST}:{SERVER_PORT}")

try:

    connection, address = server.accept()

    with connection:

        print("\nClient connected:", address)

        # STEP 3: Receive encrypted ticket
        encrypted_ticket = receive_data(connection)

        print("\nEncrypted ticket received.")

        # Decrypt ticket using server's secret key
        ticket_data = decrypt(
            encrypted_ticket, KEY_SERVER
        )

        ticket = json.loads(ticket_data.decode())

        client_name = ticket["client"]
        session_key = ticket["session_key"]

        print("Ticket belongs to:", client_name)
        print("Session key received successfully.")

        # STEP 4: Generate challenge
        nonce_server = secrets.randbelow(1000000) + 1

        challenge = json.dumps({
            "nonce_server": nonce_server
        }).encode()

        encrypted_challenge = encrypt(
            challenge, session_key
        )

        send_data(connection, encrypted_challenge)

        print("\nChallenge sent to Client.")

        # STEP 5: Receive challenge response
        encrypted_response = receive_data(connection)

        response_data = decrypt(
            encrypted_response, session_key
        )

        response = json.loads(response_data.decode())

        received_value = response["response"]

        print("Challenge response received.")

        # Verify response
        if received_value == nonce_server - 1:

            print("\n========== AUTHENTICATION ==========")
            print("Client Authentication: SUCCESS")
            print("Session Key Verification: SUCCESS")
            print("Needham-Schroeder Protocol Completed.")

        else:

            print("\nClient Authentication: FAILED")

finally:

    server.close()
    print("\nServer stopped.")
