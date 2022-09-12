from implementing_aes import aes_encryption, aes_decryption, xor_bytes

AES_BLOCK_SIZE = 16


def aes_ecb_encryption(plain: bytes, key: bytes) -> bytes:
    # Assumption: length of data is multiple of 128 bits
    cipher = []
    for j in range(len(plain) // AES_BLOCK_SIZE):
        p_j = plain[j*AES_BLOCK_SIZE:(j+1)*AES_BLOCK_SIZE]
        c_j = aes_encryption(p_j, key)
        cipher += c_j
    return bytes(cipher)


def aes_ecb_decryption(cipher: bytes, key: bytes) -> bytes:
    plain = []
    for j in range(len(cipher) // AES_BLOCK_SIZE):
        c_j = cipher[j*AES_BLOCK_SIZE:(j+1)*AES_BLOCK_SIZE]
        p_j = aes_decryption(c_j, key)
        plain += p_j
    return bytes(plain)


def aes_cbc_encryption(plain: bytes, key: bytes, iv: bytes) -> bytes:

    cipher = []

    p_1 = plain[:AES_BLOCK_SIZE]
    c_1 = aes_encryption(xor_bytes(p_1, iv), key)
    cipher += c_1

    c_j_1 = c_1
    for j in range(1, len(plain) // AES_BLOCK_SIZE):
        p_j = plain[j*AES_BLOCK_SIZE:(j+1)*AES_BLOCK_SIZE]
        c_j = aes_encryption(xor_bytes(p_j, c_j_1), key)
        cipher += c_j
        c_j_1 = c_j

    return bytes(cipher)


def aes_cbc_decryption(cipher: bytes, key: bytes, iv: bytes) -> bytes:

    plain = []

    c_1 = cipher[:AES_BLOCK_SIZE]
    o_1 = aes_decryption(c_1, key)
    p_1 = xor_bytes(o_1, iv)
    plain += p_1

    c_j_1 = c_1
    for j in range(1, len(cipher) // AES_BLOCK_SIZE):
        c_j = cipher[j*AES_BLOCK_SIZE:(j+1)*AES_BLOCK_SIZE]
        o_j = aes_decryption(c_j, key)
        p_j = xor_bytes(o_j, c_j_1)
        plain += p_j
        c_j_1 = c_j

    return bytes(plain)


if __name__ == "__main__":

    # NIST Special Publication 800-38A

    # NIST ECB-AES-128 test vector F.1
    plaintext = bytearray.fromhex('6bc1bee22e409f96e93d7e117393172a'
                                  'ae2d8a571e03ac9c9eb76fac45af8e51'
                                  '30c81c46a35ce411e5fbc1191a0a52ef'
                                  'f69f2445df4f9b17ad2b417be66c3710')

    key = bytearray.fromhex('2b7e151628aed2a6abf7158809cf4f3c')

    expected_ciphertext = bytearray.fromhex('3ad77bb40d7a3660a89ecaf32466ef97'
                                            'f5d3d58503b9699de785895a96fdbaaf'
                                            '43b1cd7f598ece23881b00e3ed030688'
                                            '7b0c785e27e8ad3f8223207104725dd4')

    ciphertext = aes_ecb_encryption(plaintext, key)
    assert (ciphertext == expected_ciphertext)

    recovered_plaintext = aes_ecb_decryption(ciphertext, key)
    assert (recovered_plaintext == plaintext)

    # NIST CBC-AES-128 test vector F.2.1
    iv = bytearray.fromhex('000102030405060708090a0b0c0d0e0f')

    expected_ciphertext = bytearray.fromhex('7649abac8119b246cee98e9b12e9197d'
                                            '5086cb9b507219ee95db113a917678b2'
                                            '73bed6b8e3c1743b7116e69e22229516'
                                            '3ff1caa1681fac09120eca307586e1a7')

    ciphertext = aes_cbc_encryption(plaintext, key, iv)
    assert (ciphertext == expected_ciphertext)

    recovered_plaintext = aes_cbc_decryption(ciphertext, key, iv)
    assert (recovered_plaintext == plaintext)
