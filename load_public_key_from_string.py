from base64 import b64decode

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


public_key_string = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3CPXhKOGh6UXbcMD4tJceGVAeNZkdCvwn8ZhVol9+S5zkaEFXxu1nMQQqoHisKhdGowFMqwBbTU7a1yibSEeaiRpSAtLrf9ggedAZHq7UbohaRXaLaqF2xub4WogJMDjts+y+NbgyE31JbNlF0AXjuBc2cQzjeEI8PvbpfE3SGH68jZcKNl9xr0LgIEp0XExtTqBA/NUL1IFfTH7RWr/SZJfMwaB+YL4rDHG0RMQBg6mDwY0Z6NSkdyfxwwEmINJv6oeesAFeomhgsk0iUzbIrqtYwT3zskU+S6hCX65jp/JoxaNXfgn3r7C7wOsExqxq/Bm2nrldDfQ/E9U+mm6OQIDAQAB'


# The data between -----BEGIN RSA PUBLIC KEY----- and -----END RSA PUBLIC KEY----- is actually just base-64 encoded DER data.
der_data = b64decode(public_key_string)

# Return RSAPublicKey object from public key string
# Deserialize a public key from DER encoded data to one of the supported asymmetric public key types.
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/#cryptography.hazmat.primitives.serialization.load_der_public_key
public_key_obj = serialization.load_der_public_key(der_data, backend=default_backend())

print(public_key_obj)           # <cryptography.hazmat.backends.openssl.rsa._RSAPublicKey object at 0x000001D107C3A160>
print(type(public_key_obj))     # <class 'cryptography.hazmat.backends.openssl.rsa._RSAPublicKey'>
