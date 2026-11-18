
import socket

from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat
)

HOST = "127.0.0.1"
PORT = 5005

print("===================================")
print("          DSS CLIENT")
print("===================================")

# Generate DSA key pair
private_key = dsa.generate_private_key(key_size=2048)
public_key = private_key.public_key()

message = input("\nEnter message to sign: ").encode()

# Generate digital signature
signature = private_key.sign(
    message,
    hashes.SHA256()
)

print("\nDigital Signature Generated Successfully")

# Export public key
public_key_data = public_key.public_bytes(
    Encoding.PEM,
    PublicFormat.SubjectPublicKeyInfo
)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    client.connect((HOST, PORT))

    # Send public key length and public key
    client.sendall(len(public_key_data).to_bytes(4, "big"))
    client.sendall(public_key_data)

    # Send message length and message
    client.sendall(len(message).to_bytes(4, "big"))
    client.sendall(message)

    # Send signature length and signature
    client.sendall(len(signature).to_bytes(4, "big"))
    client.sendall(signature)

    print("Message and Signature Sent to Server")

    result = client.recv(1024).decode()

    print("\nServer Verification Result:", result)

except ConnectionRefusedError:
    print("Connection failed. Start the Server first.")

finally:
    client.close()
