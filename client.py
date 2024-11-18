import socket

def xor_encrypt_decrypt(message, key):
    return ''.join(chr(ord(c) ^ key) for c in message)

P = 23
G = 5
private_key_client = 6
public_key_client = pow(G, private_key_client, P)

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))  # Connect to Eve
print(f"[Client] Sending public key: {public_key_client}")
client_socket.sendall(str(public_key_client).encode())

server_public_key = int(client_socket.recv(1024).decode())
print(f"[Client] Received server's public key: {server_public_key}")

shared_key = pow(server_public_key, private_key_client, P)
print(f"[Client] Shared key: {shared_key}")

try:
    while True:
        # Send a message to Bob
        message = input("[Client] Enter a message to send to Bob: ")
        encrypted_message = xor_encrypt_decrypt(message, shared_key)
        client_socket.sendall(encrypted_message.encode())
        print(f"[Client] Sent encrypted message: {encrypted_message}")

        # Receive a message from Bob
        encrypted_message = client_socket.recv(1024).decode()
        decrypted_message = xor_encrypt_decrypt(encrypted_message, shared_key)
        print(f"[Client] Received message from Bob: {decrypted_message}")
except KeyboardInterrupt:
    print("[Client] Connection closed.")
finally:
    client_socket.close()
