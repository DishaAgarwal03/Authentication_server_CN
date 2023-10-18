from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt

e = b'\xe0x\xcb\x99wT\xbf\xc6\xc5\x19F9f'

password = "abc"  # Replace with your secret password
salt = b'salt'
key = scrypt(password.encode(), salt, 32, N=2**14, r=8, p=1)

cipher = AES.new(key, AES.MODE_GCM)

d = cipher.decrypt(e)
print("decrypted: ")
print(d)

k = str(e,'UTF-8')
print("decoded: ")
print(k)