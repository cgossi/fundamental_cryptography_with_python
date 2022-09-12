import math
from implementing_aes import aes_encryption


def xor_bytes(bytes_a: bytes, bytes_b: bytes) -> bytes:
    return bytes([a ^ b for (a, b) in zip(bytes_a, bytes_b)])


def MUL(X_bytes, Y_bytes):

    X = int.from_bytes(X_bytes, 'big')
    Y = int.from_bytes(Y_bytes, 'big')

    # Constant R defined for algorithm
    R = 0xe1 << 120

    # Step 1
    x = [1 if X & (1 << i) else 0 for i in range(127, -1, -1)]

    # Steps 2 and 3
    Z_i = 0
    V_i = Y
    for i in range(128):
        if x[i] == 0:
            Z_i_1 = Z_i
        else:
            Z_i_1 = Z_i ^ V_i

        if V_i % 2 == 0:
            V_i_1 = V_i >> 1
        else:
            V_i_1 = (V_i >> 1) ^ R

        Z_i = Z_i_1
        V_i = V_i_1

    # Step 4
    return Z_i.to_bytes(16, 'big')


def GHASH(H, X):

    # Input constraint: len(X) = 128m
    m = len(X) // 16

    # Step 1
    X_blocks = [X[i*16:(i+1)*16] for i in range(m)]

    # Step 2
    Y_0 = b'\x00' * 16

    # Step 3
    Y_i_1 = Y_0
    for i in range(m):
        X_i = X_blocks[i]
        Y_i = MUL(xor_bytes(Y_i_1, X_i), H)
        Y_i_1 = Y_i

    # Step 4
    return Y_i_1


def INC_32(Y_bytes):
    Y = int.from_bytes(Y_bytes, 'big')
    Y_inc = ((Y >> 32) << 32) ^ (((Y & 0xffffffff) + 1) & 0xffffffff)
    return Y_inc.to_bytes(16, 'big')


def GCTR(K, ICB, X):

    # Step 1
    if not X:
        return b''

    # Step 2
    n = math.ceil(len(X) / 16)

    # Step 3
    X_blocks = [X[i*16:(i+1)*16] for i in range(n)]

    # Step 4
    CB = [ICB]

    # Step 5
    for i in range(1, n):
        CB_i = INC_32(CB[i-1])
        CB.append(CB_i)

    # Steps 6 and 7
    Y_blocks = []
    for i in range(n):
        X_i = X_blocks[i]
        CB_i = CB[i]
        Y_i = xor_bytes(X_i, aes_encryption(CB_i, K))
        Y_blocks.append(Y_i)

    # Step 8
    Y = b''.join(Y_blocks)

    # Step 9
    return Y


def aes_gcm_encrypt(P, K, IV, A, t):

    # Step 1
    H = aes_encryption(b'\x00' * (128 // 8), K)

    # Step 2
    len_IV = len(IV) * 8
    if len_IV == 96:
        J_0 = IV + b'\x00\x00\x00\x01'
    else:
        s = 128 * math.ceil(len_IV / 128) - len_IV
        O_s_64 = b'\x00' * ((s + 64) // 8)
        len_IV_64 = int.to_bytes(len_IV, 8, 'big')
        J_0 = GHASH(H, IV + O_s_64 + len_IV_64)

    # Step 3
    C = GCTR(K, INC_32(J_0), P)

    # Step 4
    len_C, len_A = len(C) * 8, len(A) * 8
    u = 128 * math.ceil(len_C / 128) - len_C
    v = 128 * math.ceil(len_A / 128) - len_A

    # Step 5
    O_v = b'\x00' * (v // 8)
    O_u = b'\x00' * (u // 8)
    len_A_64 = int.to_bytes(len_A, 8, 'big')
    len_C_64 = int.to_bytes(len_C, 8, 'big')
    S = GHASH(H, A + O_v + C + O_u + len_A_64 + len_C_64)

    # Step 6
    T = GCTR(K, J_0, S)[:t // 8]  # Assumes tag length multiple of 8

    # Step 7
    return C, T


if __name__ == "__main__":

    # NIST Special Publication 800-38D

    # NIST test vector 1
    key = bytearray.fromhex('11754cd72aec309bf52f7687212e8957')
    iv = bytearray.fromhex('3c819d9a9bed087615030b65')
    plaintext = bytearray.fromhex('')
    associated_data = bytearray.fromhex('')
    expected_ciphertext = bytearray.fromhex('')
    expected_tag = bytearray.fromhex('250327c674aaf477aef2675748cf6971')
    tag_length = 128

    ciphertext, auth_tag = aes_gcm_encrypt(plaintext, key, iv, associated_data, tag_length)

    assert (ciphertext == expected_ciphertext)
    assert (auth_tag == expected_tag)

    # NIST test vector 2
    key = bytearray.fromhex('fe47fcce5fc32665d2ae399e4eec72ba')
    iv = bytearray.fromhex('5adb9609dbaeb58cbd6e7275')
    plaintext = bytearray.fromhex('7c0e88c88899a779228465074797cd4c2e1498d259b54390b85e3eef1c02df60e743f1b840382c4bccaf'
                                  '3bafb4ca8429bea063')
    associated_data = bytearray.fromhex('88319d6e1d3ffa5f987199166c8a9b56c2aeba5a')
    expected_ciphertext = bytearray.fromhex('98f4826f05a265e6dd2be82db241c0fbbbf9ffb1c173aa83964b7cf5393043736365253ddb'
                                            'c5db8778371495da76d269e5db3e')
    expected_tag = bytearray.fromhex('291ef1982e4defedaa2249f898556b47')
    tag_length = 128

    ciphertext, auth_tag = aes_gcm_encrypt(plaintext, key, iv, associated_data, tag_length)

    assert (ciphertext == expected_ciphertext)
    assert (auth_tag == expected_tag)

    # NIST test vector 3
    key = bytearray.fromhex('c7d9358af0fd737b118dbf4347fd252a')
    iv = bytearray.fromhex('83de9fa52280522b55290ebe3b067286d87690560179554153cb3341a04e15c5f35390602fa07e5b5f16dc38cf0'
                           '82b11ad6dd3fab8552d2bf8d9c8981bbfc5f3b57e5e3066e3df23f078fa25bce63d3d6f86ce9fbc2c679655b958'
                           'b09a991392eb93b453ba6e7bf8242f8f61329e3afe75d0f8536aa7e507d75891e540fb1d7e')
    plaintext = bytearray.fromhex('422f46223fddff25fc7a6a897d20dc8af6cc8a37828c90bd95fa9b943f460eb0a26f29ffc483592efb64'
                                  '835774160a1bb5c0cd')
    associated_data = bytearray.fromhex('5d2b9a4f994ffaa03000149956c8932e85b1a167294514e388b73b10808f509ea73c075ecbf43c'
                                        'ecfec13c202afed62110dabf8026d237f4e765853bc078f3afe081d0a1f8d8f7556b8e42acc3cc'
                                        'e888262185048d67c55b2df1')
    expected_ciphertext = bytearray.fromhex('86eba4911578ac72ac30c25fe424da9ab625f29b5c00e36d2c24a2733dc40123dc57a8c9f1'
                                            '7a24a26c09c73ad4efbcba3bab5b')
    expected_tag = bytearray.fromhex('492305190344618cab8b40f006a57186')
    tag_length = 128

    ciphertext, auth_tag = aes_gcm_encrypt(plaintext, key, iv, associated_data, tag_length)

    assert (ciphertext == expected_ciphertext)
    assert (auth_tag == expected_tag)
