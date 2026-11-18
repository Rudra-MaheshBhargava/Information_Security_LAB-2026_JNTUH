
# ============================================================
# NEEDHAM-SCHROEDER KDC
# ============================================================

import socket
import json
import secrets

from common import (
    HOST, KDC_PORT,
    KEY_CLIENT, KEY_SERVER,
    encrypt, send_data, receive_data
)


print("==========================================")
print("       KDC SERVER STARTED")
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

        # Receive request
        request = receive_data(connection)

        client_name = request["client"]
        server_name = request["server"]
        nonce_client = request["nonce_client"]

        print("\nSession key request received.")
        print("Client:", client_name)
        print("Server:", server_name)

        # Generate session key
        session_key = secrets.token_hex(16)

        print("\nSession key generated.")

        # Create encrypted ticket for server
        ticket = {
            "client": client_name,
            "session_key": session_key
        }

        ticket_data = json.dumps(ticket).encode()

        encrypted_ticket = encrypt(
            ticket_data, KEY_SERVER
        )

        # Create response for client
        response = {
            "nonce_client": nonce_client,
            "server": server_name,
            "session_key": session_key,
            "ticket": encrypted_ticket
        }

        response_data = json.dumps(response).encode()

        encrypted_response = encrypt(
            response_data, KEY_CLIENT
        )

        send_data(connection, encrypted_response)

        print("Encrypted response sent to Client.")
        print("Server ticket generated successfully.")

finally:

    server.close()
    print("\nKDC stopped.")
