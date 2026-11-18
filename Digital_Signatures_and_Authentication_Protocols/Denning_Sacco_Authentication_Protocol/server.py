
# ============================================================
# DENNING-SACCO SERVER
# ============================================================

import socket
import json
import secrets
import time

from common import (
    HOST, SERVER_PORT,
    KEY_SERVER,
    encrypt, decrypt,
    send_data, receive_data
)


print("==========================================")
print("      DENNING-SACCO SERVER")
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

        # Decrypt using Server's long-term key
        ticket_data = decrypt(
            encrypted_ticket, KEY_SERVER
        )

        ticket = json.loads(ticket_data.decode())

        client_name = ticket["client"]
        session_key = ticket["session_key"]
        timestamp = ticket["timestamp"]

        print("Ticket belongs to:", client_name)
        print("Session key received.")

        # Verify timestamp freshness
        current_time = int(time.time())

        ticket_age = current_time - timestamp

        print("Ticket age:", ticket_age, "seconds")

        if ticket_age < -5 or ticket_age > 60:

            raise ValueError(
                "Ticket expired or timestamp is invalid!"
            )

        print("Timestamp verification: SUCCESS")

        # STEP 4: Generate random challenge
        nonce_server = secrets.randbelow(1000000) + 1

        challenge = json.dumps({
            "nonce_server": nonce_server
        }).encode()

        encrypted_challenge = encrypt(
            challenge, session_key
        )

        send_data(connection, encrypted_challenge)

        print("\nChallenge sent to Client.")

        # STEP 5: Receive Client response
        encrypted_response = receive_data(connection)

        response_data = decrypt(
            encrypted_response, session_key
        )

        response = json.loads(response_data.decode())

        received_value = response["response"]

        print("Challenge response received.")

        # Verify challenge response
        if received_value == nonce_server - 1:

            print("\n========== AUTHENTICATION ==========")
            print("Client Authentication: SUCCESS")
            print("Timestamp Verification: SUCCESS")
            print("Session Key Verification: SUCCESS")
            print("Denning-Sacco Protocol Completed.")

        else:

            print("\nClient Authentication: FAILED")

finally:

    server.close()
    print("\nServer stopped.")

print("\n========== TIMESTAMP VALIDATION ==========")

print("KDC Timestamp:", timestamp)
print("Current Timestamp:", current_time)
print("Ticket Age:", ticket_age, "seconds")

if ticket_age < -5 or ticket_age > 60:

    print("Ticket Status: EXPIRED OR INVALID")
    raise ValueError("Ticket validation failed!")

else:

    print("Ticket Status: VALID")
    print("Timestamp Verification: SUCCESS")