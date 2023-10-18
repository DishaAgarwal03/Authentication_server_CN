import socket
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from diffiehellman import DiffieHellman

# Configuration
HOST = '10.0.2.15'
PORT = 12348

# Create a socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

key_pair = DiffieHellman(group=14, key_bits=32) # automatically generate one key pair

# receive public key of server and generate shared key 
dh1_public = client_socket.recv(1024)
dh2_shared_key = key_pair.generate_shared_key(dh1_public)

# get own public key and send to client
dh2_public = key_pair.get_public_key() 
client_socket.sendall(dh2_public)

# Receive the encrypted message and tag
encrypted_data = client_socket.recv(1024)
# tag = client_socket.recv(16)

password = dh2_shared_key
salt = b'salt'  
key = PBKDF2(password, salt, dkLen=32, count=1000000)

nonce = encrypted_data[:16]  # Assuming a 128-bit nonce
ciphertext = encrypted_data[16:-16]
tag = encrypted_data[-16:]
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

# Decrypt the message
client_name = cipher.decrypt(ciphertext)

try:
    cipher.verify(tag)  # Verifies the authentication tag
    print("Decryption successful")
    print("Server requested your name. You replied with: " + str(client_name,'UTF-8'))
    
except ValueError:
    print("Authentication failed. The data may be tampered.")

client_socket.close()





