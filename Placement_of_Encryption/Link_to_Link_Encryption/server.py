
import socket
from Crypto.Cipher import AES

HOST = "127.0.0.1"
PORT = 5007

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


def decrypt_message(packet):
    nonce = packet[:12]
    tag = packet[12:28]
    ciphertext = packet[28:]

    cipher = AES.new(KEY_LINK_2, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return plaintext.decode()


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(1)

print("===================================")
print("       LINK-TO-LINK SERVER")
print("===================================")
print(f"Server listening on {HOST}:{PORT}")
print("Waiting for Router...\n")

try:
    connection, address = server.accept()

    with connection:
        print("Router connected:", address)

        packet = receive_packet(connection)

        print("\nEncrypted packet received from Router.")

        message = decrypt_message(packet)

        print("\nDecryption using Link 2 key: SUCCESS")
        print("Original Message:", message)

        connection.sendall(b"MESSAGE DELIVERED")

except (ConnectionError, ValueError) as error:
    print("Error:", error)

finally:
    server.close()
