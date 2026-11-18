
# ============================================================
# DENNING-SACCO KDC SERVER
# ============================================================

import socket
import json
import secrets
import time

from common import (
    HOST, KDC_PORT,
    KEY_CLIENT, KEY_SERVER,
    encrypt, send_data, receive_data
)


print("==========================================")
print("       DENNING-SACCO KDC SERVER")
print("==========================================")

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.setsockopt(
    socket.SOL_SOCKET,
    socket.SO_REUSEADDR,
    1
)

server.bind((HOST, KDC_PORT))
server.listen(1)

print(f"KDC listening on {HOST}:{KDC_PORT}")

try:

    connection, address = server.accept()

    with connection:

        print("\nClient connected:", address)

        # STEP 1: Receive request
        request = receive_data(connection)

        client_name = request["client"]
        server_name = request["server"]

        print("\nSession key request received.")
        print("Client:", client_name)
        print("Server:", server_name)

        # Generate session key
        session_key = secrets.token_hex(16)

        # Generate timestamp
        timestamp = int(time.time())

        print("\nSession key generated.")
        print("Timestamp:", timestamp)

        # Create Server's encrypted ticket
        ticket = {
            "client": client_name,
            "session_key": session_key,
            "timestamp": timestamp
        }

        ticket_data = json.dumps(ticket).encode()

        encrypted_ticket = encrypt(
            ticket_data, KEY_SERVER
        )

        # Create response for Client
        response = {
            "server": server_name,
            "session_key": session_key,
            "timestamp": timestamp,
            "ticket": encrypted_ticket
        }

        response_data = json.dumps(response).encode()

        encrypted_response = encrypt(
            response_data, KEY_CLIENT
        )

        # STEP 2: Send response
        send_data(connection, encrypted_response)

        print("\nEncrypted session-key response sent.")
        print("Timestamped Server ticket generated.")

finally:

    server.close()
    print("\nKDC stopped.")
