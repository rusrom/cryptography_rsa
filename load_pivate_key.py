from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


# Private key will be loaded as RSAPrivateKey object
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-loading
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )


# Serialize in bytestring without encryption
# It is also possible to serialize without encryption using NoEncryption.
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-serialization
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Print as readable string
for l in pem.decode().splitlines()[1:-1]:
    print(l)
