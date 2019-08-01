from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


PASSWORD = 'In Crypto We Trust'


# LOAD PRIVATE KEY
# Private key will be loaded as RSAPrivateKey
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-loading
with open("private_key_encrypted.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=PASSWORD.encode(),
        backend=default_backend()
    )

# Serialize in bytestring without encryption
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-serialization
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

for l in private_pem.decode().splitlines():
    print(l)


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
