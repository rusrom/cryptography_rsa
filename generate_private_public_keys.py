from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


PASSWORD = 'In Crypto We Trust'


def readable_view(val):
    for l in val.decode().splitlines():
        print(l)


# Generate PRIVATE KEY as RSAPrivateKey Object
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#module-cryptography.hazmat.primitives.asymmetric.rsa
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)


# SERIALIZE PRIVATE KEY WITH ENCRYPTION to bytestring
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-serialization
pem_encrypted = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    # encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')
    encryption_algorithm=serialization.BestAvailableEncryption(PASSWORD.encode())
)

# ENCRYPTED PRIVATE KEY to terminal
print(pem_encrypted)
readable_view(pem_encrypted)


# SERIALIZE PRIVATE KEY WITHOUT ENCRYPTION to bytestring
# It is also possible to serialize without encryption using NoEncryption.
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-serialization
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# PRIVATE KEY to terminal
print(pem)
readable_view(pem)


# Generate PUBLIC KEY as RSAPublicKey Object
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.public_key
public_key = private_key.public_key()

# Serialize PUBLIC KEY to bytestring
# For public keys you can use public_bytes() to serialize the key.
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Public key to terminal
print(public_pem)
readable_view(public_pem)


# Save serialized private key to .pem file
with open('private_key_encrypted.pem', 'wb') as f:
    f.write(pem_encrypted)

# Save serialized private key to .pem file
with open('private_key.pem', 'wb') as f:
    f.write(pem)

# Save serialized public key to .pem file
with open('public_key.pem', 'wb') as f:
    f.write(public_pem)
