import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from diffiehellman import DiffieHellman

def aes_encrypt(data,key)->bytes:
    # Encrypt the message
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    # Send the encrypted message
    encrypted_data = cipher.nonce + ciphertext + tag
    return encrypted_data

def aes_decrypt(encrypted_data,key)->bytes:
    nonce = encrypted_data[:16]  # Assuming a 128-bit nonce
    ciphertext = encrypted_data[16:-16]
    tag = encrypted_data[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    # Decrypt the message
    decrypted_data = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)  # Verifies the authentication tag
        # print("Decryption successful")
        return decrypted_data    
    except ValueError:
        print("Authentication failed. The data may be tampered.")
        exit(0)

def login():
    MAIN_SERVER_HOST = '10.0.2.15'  # The server's MAIN_SERVER_HOSTname or IP address
    MAIN_SERVER_PORT = 10200 # The port used by the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((MAIN_SERVER_HOST, MAIN_SERVER_PORT))
        # Key generation and encryption setup:
        key_pair = DiffieHellman(group=14, key_bits=32) # automatically generate one key pair    
        # get own public key and send to server
        client_public = key_pair.get_public_key() 
        s.sendall(client_public)    
        # generate shared key based on the other side's public key
        server_public = s.recv(1024)
        client_shared_key = key_pair.generate_shared_key(server_public)      
        # Use a KDF to derive an AES key from the shared key
        password = client_shared_key
        salt = b'salt'  # You should use a different salt
        key = PBKDF2(password, salt, dkLen=32, count=1000000)
        # nonce = cipher.nonce
        while True:
            encrypted_data = s.recv(256)
            data = aes_decrypt(encrypted_data=encrypted_data,key=key)
            server_msg = str(data, 'UTF-8')
            print(f"{server_msg}")
            if server_msg == "Closing Connection":
                s.close()
                exit(0)   
            elif server_msg == "Wrong choice." or server_msg=="Username already exists.":
                continue      
            elif server_msg=="You are connected":
                encrypted_data = s.recv(256)
                auth_key = aes_decrypt(encrypted_data=encrypted_data,key=key)
                auth_key = str(auth_key, 'UTF-8')
                s.close()
                break
            data = input().encode()
            encrypted_data = aes_encrypt(data=data,key=key)
            s.sendall(encrypted_data)
        #key has been received
        # print(auth_key)
        return auth_key
    
def retrieve_listener_details():
    VERIFICATION_SERVER_HOST = '10.0.2.15'  # The server's MAIN_SERVER_HOSTname or IP address
    VERIFICATION_SERVER_PORT = 10201 # The port used by the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((VERIFICATION_SERVER_HOST, VERIFICATION_SERVER_PORT))
