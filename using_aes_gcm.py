import os
import cryptography.exceptions
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import GCM


def aes_gcm_authenticated_decryption(key, iv, auth_tag, associated_data, ciphertext):
    aes_gcm_decryptor = Cipher(AES(key), GCM(iv, auth_tag)).decryptor()
    aes_gcm_decryptor.authenticate_additional_data(associated_data)
    recovered_plaintext = aes_gcm_decryptor.update(ciphertext) + aes_gcm_decryptor.finalize()
    return recovered_plaintext


if __name__ == "__main__":

    # 256-bit symmetric key
    key = os.urandom(256 // 8)

    # For AES GCM, NIST recommends 96 bit IVs
    iv = os.urandom(96 // 8)

    # Our message to be kept confidential
    plaintext = b'Fundamental Cryptography in Python'

    # Associated data
    associated_data = b'Context of using AES GCM'

    # Encrypt the plaintext (no padding required for GCM)
    aes_gcm_encryptor = Cipher(AES(key), GCM(iv)).encryptor()
    aes_gcm_encryptor.authenticate_additional_data(associated_data)
    ciphertext = aes_gcm_encryptor.update(plaintext) + aes_gcm_encryptor.finalize()
    auth_tag = aes_gcm_encryptor.tag

    # Decrypt and authenticate the ciphertext
    recovered_plaintext = aes_gcm_authenticated_decryption(key, iv, auth_tag, associated_data, ciphertext)
    assert (recovered_plaintext == plaintext)

    # Wrong key
    wrong_key = os.urandom(256 // 8)
    try:
        recovered_plaintext = aes_gcm_authenticated_decryption(wrong_key, iv, auth_tag, associated_data, ciphertext)
    except cryptography.exceptions.InvalidTag:
        pass
    else:
        # Should not happen
        assert False

    # Wrong iv
    wrong_iv = os.urandom(96 // 8)
    try:
        recovered_plaintext = aes_gcm_authenticated_decryption(key, wrong_iv, auth_tag, associated_data, ciphertext)
    except cryptography.exceptions.InvalidTag:
        pass
    else:
        # Should not happen
        assert False

    # Wrong authentication tag
    wrong_auth_tag = os.urandom(128 // 8)
    try:
        recovered_plaintext = aes_gcm_authenticated_decryption(key, iv, wrong_auth_tag, associated_data, ciphertext)
    except cryptography.exceptions.InvalidTag:
        pass
    else:
        # Should not happen
        assert False

    # Wrong associated data
    wrong_associated_data = b'Wrong Context of using AES GCM'
    try:
        recovered_plaintext = aes_gcm_authenticated_decryption(key, iv, auth_tag, wrong_associated_data, ciphertext)
    except cryptography.exceptions.InvalidTag:
        pass
    else:
        # Should not happen
        assert False

    # Wrong ciphertext
    wrong_ciphertext = ciphertext[:len(ciphertext)-1] + bytes([(ciphertext[-1] + 1) % 256])
    try:
        recovered_plaintext = aes_gcm_authenticated_decryption(key, iv, auth_tag, associated_data, wrong_ciphertext)
    except cryptography.exceptions.InvalidTag:
        pass
    else:
        # Should not happen
        assert False
