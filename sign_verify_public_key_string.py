from base64 import b64decode

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


public_key_string = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3CPXhKOGh6UXbcMD4tJceGVAeNZkdCvwn8ZhVol9+S5zkaEFXxu1nMQQqoHisKhdGowFMqwBbTU7a1yibSEeaiRpSAtLrf9ggedAZHq7UbohaRXaLaqF2xub4WogJMDjts+y+NbgyE31JbNlF0AXjuBc2cQzjeEI8PvbpfE3SGH68jZcKNl9xr0LgIEp0XExtTqBA/NUL1IFfTH7RWr/SZJfMwaB+YL4rDHG0RMQBg6mDwY0Z6NSkdyfxwwEmINJv6oeesAFeomhgsk0iUzbIrqtYwT3zskU+S6hCX65jp/JoxaNXfgn3r7C7wOsExqxq/Bm2nrldDfQ/E9U+mm6OQIDAQAB'

message_string = 'Some text to sign with private key'

signature_string = 'ae3a92dfb6ce1a5769d1ee66a7b363fd0506d35577a9a5ef40dae0339be302ce14787c8f4cd4d34087f0c1c13c0a28839aae4e06b6e5ac02a5a1c6a28afa4a1d1fc7971c91fdfb0bf731b5faee2f0bf28869341a143f45dc26ec9ad3160d921ee46b88dac1344dbb438714b47962728ce286da8ea1db79f25047d251eb0a1da95e31382de2993a4ebbb15fc041b60d7f8e9a3a5cb590905dc18e5290318e42ba3294b1cea7bb5761cf1eb2c5ffd7b4e1dad6a1b6a1748fef5a73be7e7947b8318f0c808a804e58d39f67b498a31dd38a6b55a5877bbd2cd0275a9f85ce2539334012aebfef5cd6a3576b391219364b72a4f965f7404f73fa134dc2ced0efaa8a'

signature_hacked_string = 'ae3a92dfb6ce1a5769d1ee66a7b363fd0506d35577a9a5ef40dae0339be302ce14787c8f4cd4d34087f0c1c13c0a28839aae4e06b6e5ac02a5a1c6a28afa4a1d1fc7971c91fdfb0bf731b5faee2f0bf28869341a143f45dc26ec9ad3160d921ee46b88dac1344dbb438714b47962728ce286da8ea1db79f25047d251eb0a1da95e31382de2993a4ebbb15fc041b60d7f8e9a3a5cb590905dc18e5290318e42ba3294b1cea7bb5761cf1eb2c5ffd7b4e1dad6a1b6a1748fef5a73be7e7947b8318f0c808a804e58d39f67b498a31dd38a6b55a5877bbd2cd0275a9f85ce2539334012aebfef5cd6a3576b391219364b72a4f965f7404f73fa134dc2ced0efaa8b'


def check_signature(public_key_string, message_string, signature_string):
    # Get byte string from message string
    message = message_string.encode()

    # Return the binary hex data represented by the hexadecimal string.
    signature = bytes.fromhex(signature_string)

    # Return RSAPublicKey object from public key string
    # The data between -----BEGIN RSA PUBLIC KEY----- and -----END RSA PUBLIC KEY----- is actually just base-64 encoded DER data.
    der_data = b64decode(public_key_string)

    # Deserialize a public key from DER encoded data to one of the supported asymmetric public key types.
    # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/#cryptography.hazmat.primitives.serialization.load_der_public_key
    public_key_obj = serialization.load_der_public_key(der_data, backend=default_backend())

    try:
        # Signature Verification
        # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#verification
        public_key_obj.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print('Tansaction signature OK!')
        return True
    except InvalidSignature:
        # If the signature does not match, verify() will raise an InvalidSignature exception.
        # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#verification
        # https://cryptography.io/en/latest/exceptions/#cryptography.exceptions.InvalidSignature
        print('[CRITICAL ERROR] Signature failed')
        return False


# Good signature
check_signature(public_key_string, message_string, signature_string)

# Hacked signature
check_signature(public_key_string, message_string, signature_hacked_string)
