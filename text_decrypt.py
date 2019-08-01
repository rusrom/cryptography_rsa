# Necessary for serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# Necessary for signing
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# binascii — Convert between binary and ASCII
# import binascii


PASSWORD = 'In Crypto We Trust'

# LOAD PRIVATE KEY

# Private key will be loaded as RSAPrivateKey object
# If the key is encrypted we can pass a bytes object as the password argument.
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-loading
with open("private_key_encrypted.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=PASSWORD.encode(),
        backend=default_backend()
    )


# Serialize in bytestring without encryption
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-serialization
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Print private key in readable format
for l in pem.decode().splitlines():
    print(l)


# LOAD ENCCRYPTED TEXT
with open('encoded_text.txt') as f:
    ciphertext_string = f.read()

# binascii.unhexlify(str) returns the binary data represented by the hexadecimal string.
# https://docs.python.org/3/library/binascii.html#binascii.unhexlify
# signature = binascii.unhexlify(ciphertext_string)

# Similar functionality (accepting only text string arguments, but more liberal towards whitespace) is also accessible using the bytes.fromhex() class method.
# This bytes class method returns a bytes object, decoding the given string object.
# The string must contain two hexadecimal digits per byte, with ASCII whitespace being ignored.
# https://docs.python.org/3/library/stdtypes.html#bytes.fromhex
ciphertext = bytes.fromhex(ciphertext_string)


# DECRYPT TEXT
# Once you have an encrypted message, it can be decrypted using the private key
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#decryption
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(plaintext.decode())
