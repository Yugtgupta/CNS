import socket

def xor_encrypt_decrypt(message, key):
    return ''.join(chr(ord(c) ^ key) for c in message)

P = 23
G = 5
private_key_server = 15
public_key_server = pow(G, private_key_server, P)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12346))  # Server listens here
server_socket.listen(1)
print("[Server] Waiting for connection...")
conn, addr = server_socket.accept()
print(f"[Server] Connected to {addr}")

client_public_key = int(conn.recv(1024).decode())
print(f"[Server] Received client's public key: {client_public_key}")

print(f"[Server] Sending public key: {public_key_server}")
conn.sendall(str(public_key_server).encode())

shared_key = pow(client_public_key, private_key_server, P)
print(f"[Server] Shared key: {shared_key}")

try:
    while True:
        # Receive a message from the client
        encrypted_message = conn.recv(1024).decode()
        decrypted_message = xor_encrypt_decrypt(encrypted_message, shared_key)
        print(f"[Server] Received message from Client: {decrypted_message}")

        # Send a message back to the client
        message = input("[Server] Enter a message to send to the client: ")
        encrypted_message = xor_encrypt_decrypt(message, shared_key)
        conn.sendall(encrypted_message.encode())
        print(f"[Server] Sent encrypted message: {encrypted_message}")
except KeyboardInterrupt:
    print("[Server] Connection closed.")
finally:
    conn.close()
    server_socket.close()
