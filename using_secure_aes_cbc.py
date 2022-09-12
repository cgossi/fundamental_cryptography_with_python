import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC


if __name__ == "__main__":

    # Our message to be kept confidential
    plaintext = b'Fundamental Cryptography in Python'
    print(f"Plaintext: {plaintext}")

    # 256 bit symmetric key
    key = os.urandom(32)

    # 128 random bit initialization vector (IV) required for CBC mode
    iv = os.urandom(16)

    # AES CBC Cipher
    aes_cbc_cipher = Cipher(AES(key), CBC(iv))

    # Encrypt without padding
    ciphertext = aes_cbc_cipher.encryptor().update(plaintext)
    print(f"Ciphertext (no padding): {ciphertext}")

    # Decrypt without padding
    recovered_plaintext = aes_cbc_cipher.decryptor().update(ciphertext)
    print(f"Recovered plaintext (no padding): {recovered_plaintext}")

    # Pad the plaintext
    aes_block_size_in_bits = 128
    pkcs7_padder = padding.PKCS7(aes_block_size_in_bits).padder()
    padded_plaintext = pkcs7_padder.update(plaintext) + pkcs7_padder.finalize()

    # Encrypt with padding
    ciphertext = aes_cbc_cipher.encryptor().update(padded_plaintext)
    print(f"Ciphertext (with padding): {ciphertext}")

    # Decrypt with padding
    recovered_plaintext = aes_cbc_cipher.decryptor().update(ciphertext)

    # Unpad the plaintext
    pkcs7_unpadder = padding.PKCS7(aes_block_size_in_bits).unpadder()
    unpadded_recovered_plaintext = pkcs7_unpadder.update(recovered_plaintext) + pkcs7_unpadder.finalize()
    print(f"Recovered plaintext (with padding): {unpadded_recovered_plaintext}")
    assert (plaintext == unpadded_recovered_plaintext)

    # Encrypt mandelbrot.ppm
    with open("mandelbrot.ppm", "rb") as image:
        image_file = image.read()
        image_bytes = bytearray(image_file)

    # Keep ppm header (17 bytes) and only encrypt the body
    header_size = 17
    image_header = image_bytes[:header_size]
    image_body = image_bytes[header_size:]

    # Pad the image body
    pkcs7_padder = padding.PKCS7(aes_block_size_in_bits).padder()
    padded_image_body = pkcs7_padder.update(image_body) + pkcs7_padder.finalize()

    # Encrypt the image body
    encrypted_image_body = aes_cbc_cipher.encryptor().update(padded_image_body)

    # Create and save full encrypted image
    encrypted_image = image_header + encrypted_image_body[:len(image_body)]
    with open("mandelbrot_aes_cbc_encrypted.ppm", "wb") as image_encrypted:
        image_encrypted.write(encrypted_image)
