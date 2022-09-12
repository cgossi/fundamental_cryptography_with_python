import os
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.exceptions import InvalidSignature


def aes_256_cbc_encrypt(plaintext, key):

    # Pad the data
    pkcs7_padder = padding.PKCS7(AES.block_size).padder()
    padded_plaintext = pkcs7_padder.update(plaintext) + pkcs7_padder.finalize()

    # Generate new random 128 IV required for CBC mode
    iv = os.urandom(128 // 8)

    # AES CBC Cipher
    aes_256_cbc_cipher = Cipher(AES(key), CBC(iv))

    # Encrypt padded plaintext
    ciphertext = aes_256_cbc_cipher.encryptor().update(padded_plaintext)

    return iv + ciphertext


def aes_256_cbc_decrypt(cipherdata, key):

    # Extract iv and ciphertext
    iv = cipherdata[:16]
    ciphertext = cipherdata[16:]

    # Recover padded plaintext
    aes_256_cbc_cipher = Cipher(AES(key), CBC(iv))
    recovered_padded_plaintext = aes_256_cbc_cipher.decryptor().update(ciphertext)

    # Remove padding
    pkcs7_unpadder = padding.PKCS7(AES.block_size).unpadder()
    recovered_plaintext = pkcs7_unpadder.update(recovered_padded_plaintext) + pkcs7_unpadder.finalize()

    return recovered_plaintext


def create_hmac_sha_256_tag(data, key):
    hash_function = hashes.SHA256()
    h = hmac.HMAC(key, hash_function)
    h.update(data)
    hmac_tag = h.finalize()
    return hmac_tag


def verify_hmac_sha_256_tag(tag, data, key):
    hash_function = hashes.SHA256()
    h = hmac.HMAC(key, hash_function)
    h.update(data)
    h.verify(tag)


if __name__ == "__main__":

    # Pre-condition: 2 keys for AES-256 CBC and HMAC-SHA-256
    enc_key = os.urandom(256 // 8)
    mac_key = os.urandom(256 // 8)

    # Sender to encrypt-then-MAC
    plaintext = b'Fundamental Cryptography in Python'
    cipherdata = aes_256_cbc_encrypt(plaintext, enc_key)
    mac_tag = create_hmac_sha_256_tag(cipherdata, mac_key)

    # Transfer to receiver
    received_cipherdata = cipherdata
    received_mac_tag = mac_tag

    # Receiver to MAC-then-decrypt
    try:
        verify_hmac_sha_256_tag(received_mac_tag, received_cipherdata, mac_key)
    except InvalidSignature:
        assert False
    else:
        recovered_plaintext = aes_256_cbc_decrypt(received_cipherdata, enc_key)
        assert (recovered_plaintext == plaintext)
