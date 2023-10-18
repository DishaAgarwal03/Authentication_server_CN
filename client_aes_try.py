import socket
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt

# Configuration
HOST = '10.0.2.15'
PORT = 12349

# Key generation and encryption setup (must match server)
password = "abc"  # Replace with your secret password
salt = b'salt'
key = scrypt(password.encode(), salt, 32, N=2**14, r=8, p=1)

# cipher = AES.new(key, AES.MODE_GCM)

# Create a socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

# Receive the encrypted message and tag
encrypted_data = client_socket.recv(1024)
# tag = client_socket.recv(16)

nonce = encrypted_data[:16]  # Assuming a 128-bit nonce
ciphertext = encrypted_data[16:-16]
tag = encrypted_data[-16:]
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

# Decrypt the message
client_name = cipher.decrypt(ciphertext)
# print(ciphertext)
try:
    cipher.verify(tag)  # Verifies the authentication tag
    print("Decryption successful")
    print("Server requested your name. You replied with: " + str(client_name,'UTF-8'))
    
except ValueError:
    print("Authentication failed. The data may be tampered.")

client_socket.close()





