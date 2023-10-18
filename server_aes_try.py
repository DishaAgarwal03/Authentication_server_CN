import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt

# Configuration
HOST = '10.0.2.15'
PORT = 12349

# Key generation and encryption setup
password = "abc"  # Replace with your secret password
salt = b'salt'
key = scrypt(password.encode(), salt, 32, N=2**14, r=8, p=1)

cipher = AES.new(key, AES.MODE_GCM)
nonce = cipher.nonce

# Create a socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen()

print("Server is listening on {}:{}".format(HOST, PORT))

while True:
    client_socket, addr = server_socket.accept()
    print("Connection from", addr)

    client_name = input("Enter your name: ").encode()
    
    print("Client name is: "+ str(client_name,'UTF-8'))
    # Encrypt the message
    ciphertext, tag = cipher.encrypt_and_digest(client_name)
    # print(ciphertext)
    # Send the encrypted message
    encrypted_data = nonce + ciphertext + tag
    client_socket.sendall(encrypted_data)
    # client_socket.sendall(tag)
    
    client_socket.close()
    break
server_socket.close()
