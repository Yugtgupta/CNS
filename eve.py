import socket

def xor_encrypt_decrypt(message, key):
    return ''.join(chr(ord(c) ^ key) for c in message)

P = 23
G = 5
private_key_eve = 12
public_key_eve = pow(G, private_key_eve, P)

eve_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
eve_server.bind(('localhost', 12345))  # Client connects here
eve_server.listen(1)
print("[Eve] Waiting for client...")
client_conn, client_addr = eve_server.accept()
print(f"[Eve] Intercepted connection from {client_addr}")

client_public_key = int(client_conn.recv(1024).decode())
print(f"[Eve] Intercepted client's public key: {client_public_key}")

print(f"[Eve] Sending fake public key to client: {public_key_eve}")
client_conn.sendall(str(public_key_eve).encode())

shared_key_client = pow(client_public_key, private_key_eve, P)
print(f"[Eve] Shared key with client: {shared_key_client}")

eve_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
eve_client.connect(('localhost', 12346))  # Connect to the real server
print("[Eve] Connecting to real server...")

print(f"[Eve] Sending fake public key to server: {public_key_eve}")
eve_client.sendall(str(public_key_eve).encode())

server_public_key = int(eve_client.recv(1024).decode())
print(f"[Eve] Intercepted server's public key: {server_public_key}")

shared_key_server = pow(server_public_key, private_key_eve, P)
print(f"[Eve] Shared key with server: {shared_key_server}")

try:
    while True:
        # Intercept a message from the client
        encrypted_message = client_conn.recv(1024).decode()
        decrypted_message = xor_encrypt_decrypt(encrypted_message, shared_key_client)
        print(f"[Eve] Decrypted message from client: {decrypted_message}")
        modified_message = "Hi, you are hacked"
        re_encrypted_message = xor_encrypt_decrypt(modified_message, shared_key_server)
        print(f"[Eve] Forwarding modified message to server: {modified_message}")
        eve_client.sendall(re_encrypted_message.encode())

        # Intercept a message from the server
        encrypted_message = eve_client.recv(1024).decode()
        decrypted_message = xor_encrypt_decrypt(encrypted_message, shared_key_server)
        print(f"[Eve] Decrypted message from server: {decrypted_message}")
        modified_message = "Bob says: You are hacked!"
        re_encrypted_message = xor_encrypt_decrypt(modified_message, shared_key_client)
        print(f"[Eve] Forwarding modified message to client: {modified_message}")
        client_conn.sendall(re_encrypted_message.encode())
except KeyboardInterrupt:
    print("[Eve] Connection closed.")
finally:
    client_conn.close()
    eve_client.close()
    eve_server.close()
