
# ============================================================
# COMMON FUNCTIONS
# DENNING-SACCO AUTHENTICATION PROTOCOL
# ============================================================

import hashlib
import hmac
import json
import secrets

HOST = "127.0.0.1"

KDC_PORT = 5002
SERVER_PORT = 5003

# Long-term secret keys
KEY_CLIENT = "client_shared_secret_2026"
KEY_SERVER = "server_shared_secret_2026"


# Educational encryption demonstration
def encrypt(data, key):

    key_bytes = key.encode()
    nonce = secrets.token_bytes(16)

    stream = b""
    counter = 0

    while len(stream) < len(data):

        block = hashlib.sha256(
            key_bytes + nonce + counter.to_bytes(4, "big")
        ).digest()

        stream += block
        counter += 1

    ciphertext = bytes(
        a ^ b for a, b in zip(data, stream)
    )

    tag = hmac.new(
        key_bytes,
        nonce + ciphertext,
        hashlib.sha256
    ).hexdigest()

    return {
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag
    }


# Decryption and authentication
def decrypt(encrypted_data, key):

    key_bytes = key.encode()

    nonce = bytes.fromhex(encrypted_data["nonce"])
    ciphertext = bytes.fromhex(encrypted_data["ciphertext"])

    expected_tag = hmac.new(
        key_bytes,
        nonce + ciphertext,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(
        expected_tag, encrypted_data["tag"]
    ):
        raise ValueError("Message authentication failed!")

    stream = b""
    counter = 0

    while len(stream) < len(ciphertext):

        block = hashlib.sha256(
            key_bytes + nonce + counter.to_bytes(4, "big")
        ).digest()

        stream += block
        counter += 1

    return bytes(
        a ^ b for a, b in zip(ciphertext, stream)
    )


# Send JSON data
def send_data(connection, data):

    message = json.dumps(data).encode() + b"\n"

    connection.sendall(message)


# Receive JSON data
def receive_data(connection):

    buffer = b""

    while not buffer.endswith(b"\n"):

        chunk = connection.recv(4096)

        if not chunk:
            raise ConnectionError("Connection closed.")

        buffer += chunk

    return json.loads(buffer.decode())
