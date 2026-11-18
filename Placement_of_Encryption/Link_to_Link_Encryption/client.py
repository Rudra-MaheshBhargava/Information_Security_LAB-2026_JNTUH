
import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

HOST = "127.0.0.1"
PORT = 5006

KEY_LINK_1 = b"Link1Key-2026!!!"


def encrypt_message(message):
    nonce = get_random_bytes(12)

    cipher = AES.new(KEY_LINK_1, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())

    return nonce + tag + ciphertext


def main():
    print("===================================")
    print("       LINK-TO-LINK CLIENT")
    print("===================================")

    message = input("\nEnter message: ")

    packet = encrypt_message(message)

    print("\nOriginal Message:", message)
    print("Encryption using Link 1 key: SUCCESS")
    print("Encrypted packet generated.")

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client.connect((HOST, PORT))

        # Send packet length followed by encrypted packet
        client.sendall(len(packet).to_bytes(4, "big") + packet)

        print("Encrypted message sent to Router.")

        response = client.recv(1024).decode()
        print("\nRouter Response:", response)

    except ConnectionRefusedError:
        print("Connection failed. Start the Router first.")

    except OSError as error:
        print("Communication Error:", error)

    finally:
        client.close()


if __name__ == "__main__":
    main()
