from diffiehellman import DiffieHellman
from cryptography.hazmat.primitives.asymmetric import dh

# automatically generate two key pairs
# dh1 = DiffieHellman(group=14, key_bits=256)
# dh2 = DiffieHellman(group=14, key_bits=256)

# Define the key length and group parameters
key_bits = 256  # Use 256 bits for private and public keys
group = dh.DHParameters.generate(256)  # Generate parameters for 256-bit DH
# Create a Diffie-Hellman key pair
dh1 = dh.DHPrivateKey.generate(parameters=group)

# Define the key length and group parameters
key_bits = 256  # Use 256 bits for private and public keys
group = dh.DHParameters.generate(256)  # Generate parameters for 256-bit DH
# Create a Diffie-Hellman key pair
dh2 = dh.DHPrivateKey.generate(parameters=group)


# get both public keys
dh1_public = dh1.get_public_key()
dh2_public = dh2.get_public_key()

# generate shared key based on the other side's public key
dh1_shared = dh1.generate_shared_key(dh2_public)
dh2_shared = dh2.generate_shared_key(dh1_public)

# the shared keys should be equal
if dh1_shared == dh2_shared:
    print("Same")
else:
    print("different")