import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from diffiehellman import DiffieHellman

# Configuration
HOST = '10.0.2.15'
PORT = 12348

# Create a socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen()

print("Server is listening on {}:{}".format(HOST, PORT))

while True:
    client_socket, addr = server_socket.accept()
    print("Connection from", addr)
    
    # Key generation and encryption setup:
    key_pair = DiffieHellman(group=14, key_bits=32) # automatically generate one key pair
    
    # get own public key and send to client
    dh1_public = key_pair.get_public_key() 
    client_socket.sendall(dh1_public)
    
    # generate shared key based on the other side's public key
    dh2_public = client_socket.recv(1024)
    dh1_shared_key = key_pair.generate_shared_key(dh2_public)  
    
    # Use a KDF to derive an AES key from the shared key
    password = dh1_shared_key
    salt = b'salt'  # You should use a different salt
    key = PBKDF2(password, salt, dkLen=32, count=1000000)

    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce

    client_name = input("Enter your name: ").encode()
    # Encrypt the message
    ciphertext, tag = cipher.encrypt_and_digest(client_name)

    # Send the encrypted message
    encrypted_data = nonce + ciphertext + tag
    client_socket.sendall(encrypted_data)
    # client_socket.sendall(tag)
    
    client_socket.close()
    break
server_socket.close()
