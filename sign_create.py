# Necessary for serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# Necessary for signing
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# binascii — Convert between binary and ASCII
# import binascii


PASSWORD = 'In Crypto We Trust'

MESSAGE = 'Bitcoin[a] (₿) is a cryptocurrency. It is a decentralized digital currency without a central bank or single administrator that can be sent from user to user on the peer-to-peer bitcoin network without the need for intermediaries'


# Private key will be loaded as RSAPrivateKey object
# If the key is encrypted we can pass a bytes object as the password argument.
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-loading
with open("private_key_encrypted.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=PASSWORD.encode(),
        backend=default_backend()
    )

# SIGNING MESSAGE
# MESSAGE must be bytes-like
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#signing
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.sign
signature = private_key.sign(
    MESSAGE.encode(),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Return the hexadecimal representation of the binary data. Every byte of data is converted into the corresponding 2-digit hex representation.
# The returned bytes object is therefore twice as long as the length of data.
# https://docs.python.org/3/library/binascii.html#binascii.hexlify
# signature_string = binascii.hexlify(signature).decode()

# Similar functionality (but returning a text string) is also conveniently accessible using the bytes.hex() method.
# https://docs.python.org/3/library/stdtypes.html#bytes.hex
signature_string = signature.hex()

print('Signature:')
print(signature_string)

with open('signature.txt', 'w') as f:
    f.write(signature_string)
