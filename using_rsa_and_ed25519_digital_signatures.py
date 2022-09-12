import cryptography.exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def use_rsa_pss_digital_signatures():

    # RSA-PSS
    sha256 = hashes.SHA256()
    pss_padding = padding.PSS(mgf=padding.MGF1(sha256), salt_length=padding.PSS.MAX_LENGTH)

    # Public-private key creation
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Signature creation
    message = b'Fundamental Cryptography in Python'
    signature = private_key.sign(message, pss_padding, sha256)

    # Signature verification
    try:
        public_key.verify(signature, message, pss_padding, sha256)
    except cryptography.exceptions.InvalidSignature:
        # Should not happen
        assert False

    # Wrong message
    wrong_message = b''
    try:
        public_key.verify(signature, wrong_message, pss_padding, sha256)
    except cryptography.exceptions.InvalidSignature:
        pass
    else:
        # Should not happen
        assert False

    # Wrong signature
    wrong_signature = b''
    try:
        public_key.verify(wrong_signature, message, pss_padding, sha256)
    except cryptography.exceptions.InvalidSignature:
        pass
    else:
        # Should not happen
        assert False

    # Wrong public key
    wrong_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong_public_key = wrong_private_key.public_key()
    try:
        wrong_public_key.verify(signature, message, pss_padding, sha256)
    except cryptography.exceptions.InvalidSignature:
        pass
    else:
        # Should not happen
        assert False


def use_ed25519_digital_signatures():

    # Ed25519

    # Public-private key creation
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Signature creation
    message = b'Fundamental Cryptography in Python'
    signature = private_key.sign(message)

    # Signature verification
    try:
        public_key.verify(signature, message)
    except cryptography.exceptions.InvalidSignature:
        # Should not happen
        assert False

    # Wrong message
    wrong_message = b''
    try:
        public_key.verify(signature, wrong_message)
    except cryptography.exceptions.InvalidSignature:
        pass
    else:
        # Should not happen
        assert False

    # Wrong signature
    wrong_signature = b''
    try:
        public_key.verify(wrong_signature, message)
    except cryptography.exceptions.InvalidSignature:
        pass
    else:
        # Should not happen
        assert False

    # Wrong public key
    wrong_private_key = Ed25519PrivateKey.generate()
    wrong_public_key = wrong_private_key.public_key()
    try:
        wrong_public_key.verify(signature, message)
    except cryptography.exceptions.InvalidSignature:
        pass
    else:
        # Should not happen
        assert False


if __name__ == "__main__":

    use_rsa_pss_digital_signatures()
    use_ed25519_digital_signatures()
