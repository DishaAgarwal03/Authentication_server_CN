import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet,InvalidToken

def getKey()->bytes:
    password_provided = "password"  # This is input in the form of a string
    password = password_provided.encode()  # Convert to type bytes
    salt = b'salt_'  # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once
    return key

def encryptToStore(key,plaintext)->str:
    f = Fernet(key=key)
    return f.encrypt(plaintext).decode()

def decryptFromStore(key,enctext)->str:
    f = Fernet(key=key)
    try:
        decrypted = f.decrypt(enctext)
        print("Valid Key - Successfully decrypted")
        return decrypted.decode()
    except InvalidToken as e:  # Catch any InvalidToken exceptions if the correct key was not provided
        print("Invalid Key - Unsuccessfully decrypted")
        return '-1'


# def main():
#     plaintext = "My name is Dhruv".encode()
#     key = getKey()
#     enctxt = encryptToStore(key=key,plaintext=plaintext)
#     print(enctxt.decode())
#     print(decryptFromStore(key=key,enctext=enctxt).decode())
#     print("END")

# if __name__ == "__main__":
#     main()