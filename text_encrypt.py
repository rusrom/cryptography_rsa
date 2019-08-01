'''
The nature of the RSA cryptosystem is such that you cannot encrypt a value longer than the modulus (and, in fact, it must shorter to be able to encrypt it safely as RSA's security is partially premised on padding).

If we want to encrypt a larger payload we need to instead construct a system such that you encrypt your payload using a symmetric cipher (make sure it's authenticated encryption! cryptography provides a construction called Fernet that can do this),and then encrypt the symmetric key using your RSA public key.
We can then send both ciphertexts over to the recipient.
The recipient can decrypt the RSA encrypted key using the private key they hold and decrypt the larger ciphertext with the resulting key.
'''

# Necessary for serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# Necessary for encryption
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# binascii — Convert between binary and ASCII
# import binascii


TEXT_TO_ENCRYPT = 'This is a “Hazardous Materials” module. This module is full of land mines, dragons, and dinosaurs with laser guns.'


# LOAD PUBLIC KEY

# Public key will be loaded as RSAPublicKey object
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/#cryptography.hazmat.primitives.serialization.load_pem_public_key
with open("public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

# Serialize PUBLIC KEY to bytestring
# For public keys you can use public_bytes() to serialize the key.
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-serialization
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

for l in public_pem.decode().splitlines():
    print(l)


# TEXT ENCRYPTION USING PUBLIC KEY

# RSA encryption is interesting because encryption is performed using the public key, meaning anyone can encrypt data.
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#encryption
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey
ciphertext = public_key.encrypt(
    TEXT_TO_ENCRYPT.encode(),  # MESSAGE must be bytes string
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# CONVERT CIPHERTEXT TO STRING

# Return the hexadecimal representation of the binary data. Every byte of data is converted into the corresponding 2-digit hex representation.
# The returned bytes object is therefore twice as long as the length of data.
# https://docs.python.org/3/library/binascii.html#binascii.hexlify
# ciphertext_string = binascii.hexlify(ciphertext).decode()

# Similar functionality (but returning a text string) is also conveniently accessible using the bytes.hex() method.
# https://docs.python.org/3/library/stdtypes.html#bytes.hex
ciphertext_string = ciphertext.hex()

print('Encoded text:')
print(ciphertext_string)

# SAVE ENCRYPTED TEXT TO FILE
with open('encoded_text.txt', 'w') as f:
    f.write(ciphertext_string)
