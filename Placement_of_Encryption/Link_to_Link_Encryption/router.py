
import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

HOST = "127.0.0.1"

CLIENT_PORT = 5006
SERVER_PORT = 5007

KEY_LINK_1 = b"Link1Key-2026!!!"
KEY_LINK_2 = b"Link2Key-2026!!!"


def receive_exact(connection, size):
    data = b""

    while len(data) < size:
        chunk = connection.recv(size - len(data))

        if not chunk:
            raise ConnectionError("Connection closed unexpectedly.")

        data += chunk

    return data


def receive_packet(connection):
    length = int.from_bytes(receive_exact(connection, 4), "big")
    return receive_exact(connection, length)


def send_packet(connection, packet):
    connection.sendall(len(packet).to_bytes(4, "big") + packet)


def decrypt_message(packet):
    nonce = packet[:12]
    tag = packet[12:28]
    ciphertext = packet[28:]

    cipher = AES.new(KEY_LINK_1, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return plaintext


def encrypt_message(plaintext):
    nonce = get_random_bytes(12)

    cipher = AES.new(KEY_LINK_2, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return nonce + tag + ciphertext


router = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
router.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
router.bind((HOST, CLIENT_PORT))
router.listen(1)

print("===================================")
print("          NETWORK ROUTER")
print("===================================")
print(f"Router listening for Client on {CLIENT_PORT}")
print("Waiting for Client...\n")

try:
    client_connection, client_address = router.accept()

    with client_connection:
        print("Client connected:", client_address)

        packet = receive_packet(client_connection)

        print("\nEncrypted packet received from Client.")

        # Decrypt data using Link 1 key
        plaintext = decrypt_message(packet)

        print("Link 1 decryption: SUCCESS")
        print("Plaintext recovered at Router:", plaintext.decode())

        # Encrypt data using Link 2 key
        new_packet = encrypt_message(plaintext)

        print("\nRe-encrypting data using Link 2 key...")

        # Forward encrypted data to Server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_connection:
            server_connection.connect((HOST, SERVER_PORT))

            send_packet(server_connection, new_packet)

            print("Encrypted packet forwarded to Server.")

            response = server_connection.recv(1024).decode()
            print("Server response:", response)

        client_connection.sendall(b"Router forwarded message successfully.")

except (ConnectionError, ValueError, OSError) as error:
    print("Router Error:", error)

finally:
    router.close()
