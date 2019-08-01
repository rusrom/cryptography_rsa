# Necessary for serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# Necessary for verifying signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# If the signature does not match, verify() will raise an InvalidSignature exception.
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.verify
from cryptography.exceptions import InvalidSignature

# binascii — Convert between binary and ASCII
# import binascii


MESSAGE = 'Bitcoin[a] (₿) is a cryptocurrency. It is a decentralized digital currency without a central bank or single administrator that can be sent from user to user on the peer-to-peer bitcoin network without the need for intermediaries'


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


# Load SIGNATURE
with open('signature.txt') as f:
    signature_string = f.read()

print('Signature string:')
print(signature_string)

# Return the binary data represented by the hexadecimal string.
# https://docs.python.org/3/library/binascii.html#binascii.unhexlify
# signature = binascii.unhexlify(signature_string)

# Similar functionality (accepting only text string arguments, but more liberal towards whitespace) is also accessible using the bytes.fromhex() class method.
# This bytes class method returns a bytes object, decoding the given string object.
# The string must contain two hexadecimal digits per byte, with ASCII whitespace being ignored.
# https://docs.python.org/3/library/stdtypes.html#bytes.fromhex
signature = bytes.fromhex(signature_string)

print('Signature bytes:')
print(signature)


# VERIFY SIGNATURE
# MESSAGE must be bytes-like
# If the signature does not match, verify() will raise an InvalidSignature exception.
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.verify
try:
    public_key.verify(
        signature,
        MESSAGE.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print('Signature OK!')
except InvalidSignature:
    print('[CRITICAL ERROR] Signature failed')
