from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.hashes import SHA256


if __name__ == "__main__":

    # Create private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    p = private_key.private_numbers().p
    q = private_key.private_numbers().q
    print(f"p: {p}")
    print(f"q: {q}")

    # Create public key
    public_key = private_key.public_key()

    n = public_key.public_numbers().n
    e = public_key.public_numbers().e
    print(f"n: {n}")
    print(f"e: {e}")

    # Encrypt with public key
    plaintext = b'Fundamental Cryptography in Python'

    oaep_padding = padding.OAEP(mgf=padding.MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None)
    ciphertext = public_key.encrypt(plaintext, oaep_padding)

    print(f"plaintext: {plaintext}")
    print(f"ciphertext: {ciphertext}")

    # Decrypt with private key
    recovered_plaintext = private_key.decrypt(ciphertext, oaep_padding)

    assert (recovered_plaintext == plaintext)

    # Verify that 190 bytes can be encrypted
    plaintext = b'\xff' * 190
    public_key.encrypt(plaintext, oaep_padding)

    # Verify 191 bytes can't be encrypted, as 191 > 256 - 64 - 2 = 190,
    # which is the limit due the OAEP definition in RFC 3447 ch. 7.1.1
    try:
        plaintext = b'\xff' * 191
        public_key.encrypt(plaintext, oaep_padding)
    except ValueError:
        pass
    else:
        assert False

