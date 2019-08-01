from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


PASSWORD = 'In Crypto We Trust'


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

# Print as readable string
for l in pem.decode().splitlines():
    print(l)
