import socket
import threading
import random
from Crypto.Util.number import isPrime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def is_primitive_root(g, p):
    phi = p - 1
    factors = set()
    i = 2
    while i * i <= phi:
        if phi % i == 0:
            factors.add(i)
            while phi % i == 0:
                phi //= i
        i += 1
    if phi > 1:
        factors.add(phi)
    return all(pow(g, (p - 1) // factor, p) != 1 for factor in factors)

def generate_keypair(p, g):
    private_key = random.randint(1, p - 1)
    public_key = pow(g, private_key, p)
    return private_key, public_key

def calculate_shared_secret(private_key, other_public_key, p):
    return pow(other_public_key, private_key, p)

def generate_rsa_key(shared_secret):
    random.seed(shared_secret)
    return RSA.generate(2048)

def encrypt_message(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message.encode())

def decrypt_message(encrypted_message, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_message).decode()

def receive_messages(sock, private_key):
    while True:
        try:
            encrypted_message = sock.recv(1024)
            if not encrypted_message:
                break
            decrypted_message = decrypt_message(encrypted_message, private_key)
            print(f"Received (decrypted): {decrypted_message}")
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

def client():
    host = '0.0.0.0'
    port = 54321

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.bind((host, port))
    client_socket.listen(1)

    print(f"Client is listening on {host}:{port}")
    print("Waiting for Server to connect...")

    conn, addr = client_socket.accept()
    print(f"Connected to Server at {addr}")

    p = int(input("Enter a prime number p: "))
    while not isPrime(p):
        p = int(input("The number is not prime. Please enter a prime number p: "))

    g = int(input(f"Enter a generator g (primitive root of {p}): "))
    while not is_primitive_root(g, p):
        g = int(input(f"{g} is not a primitive root of {p}. Please enter a valid generator g: "))

    private_key, public_key = generate_keypair(p, g)
    print(f"Diffie-Hellman Private Key: {private_key}")
    print(f"Diffie-Hellman Public Key: {public_key}")

    conn.send(f"{p},{g},{public_key}".encode())

    client2_public_key = int(conn.recv(1024).decode())
    print(f"Received Diffie-Hellman Public Key from Server: {client2_public_key}")

    shared_secret = calculate_shared_secret(private_key, client2_public_key, p)
    print(f"Shared Secret: {shared_secret}")

    rsa_key = generate_rsa_key(shared_secret)
    print("RSA Key Pair Generated")

    conn.send(rsa_key.publickey().export_key())
    server_public_key = RSA.import_key(conn.recv(1024))
    print("RSA Public Keys Exchanged")

    receive_thread = threading.Thread(target=receive_messages, args=(conn, rsa_key))
    receive_thread.start()

    while True:
        message = input("Enter message to send (or 'quit' to exit): ")
        if message.lower() == 'quit':
            break
        encrypted_message = encrypt_message(message, server_public_key)
        conn.send(encrypted_message)
        print(f"Sent (encrypted): {encrypted_message.hex()}")

    conn.close()
    client_socket.close()

if __name__ == "__main__":
    client()
