import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac


if __name__ == "__main__":

    # Message
    message = b'Fundamental Cryptography in Python'

    # 256-bit symmetric key (32 bytes)
    key_length = 32
    key = os.urandom(key_length)

    # Construct HMAC-SHA-256
    hash_function = hashes.SHA256()
    h = hmac.HMAC(key, hash_function)

    # Calculate MAC tag
    h.update(message)
    mac_tag = h.finalize()

    # Verify
    h = hmac.HMAC(key, hash_function)
    h.update(message)
    h.verify(mac_tag)

    # Verify with wrong message
    wrong_message = b'Fundamental Cryptography in Java'
    h = hmac.HMAC(key, hash_function)
    h.update(wrong_message)

    try:
        h.verify(mac_tag)
    except InvalidSignature:
        pass
    else:
        assert False

    # Verify with wrong key
    wrong_key = os.urandom(key_length)
    h = hmac.HMAC(wrong_key, hash_function)
    h.update(message)

    try:
        h.verify(mac_tag)
    except InvalidSignature:
        pass
    else:
        assert False

    # Verify with wrong mac tag
    wrong_mac_tag = os.urandom(key_length)
    h = hmac.HMAC(key, hash_function)
    h.update(message)

    try:
        h.verify(wrong_mac_tag)
    except InvalidSignature:
        pass
    else:
        assert False

    # Verify with wrong hash function
    wrong_hash_function = hashes.SHA3_256()
    h = hmac.HMAC(key, wrong_hash_function)
    h.update(message)

    try:
        h.verify(mac_tag)
    except InvalidSignature:
        pass
    else:
        assert False
