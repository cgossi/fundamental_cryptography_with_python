from cryptography.hazmat.primitives import hashes


def xor(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for (x, y) in zip(a, b)])


def H(H_A, message):
    H = hashes.Hash(H_A)
    H.update(message)
    return H.finalize()


def hmac(H_A, K, text):

    # HMAC Parameters and Symbols
    B, L = H_A.block_size, H_A.digest_size
    ipad = b'\x36' * B
    opad = b'\x5c' * B

    # HMAC SPECIFICATION
    if len(K) == B:
        K_0 = K
    elif len(K) > B:
        K_0 = H(H_A, K) + b'\x00' * (B-L)
    else:
        K_0 = K + b'\x00' * (B-len(K))

    return H(H_A, xor(K_0, opad) + H(H_A, xor(K_0, ipad) + text))


if __name__ == "__main__":

    # NIST FIPS PUB 198-1 The Keyed-Hash Message Authentication Code (HMAC)

    # HMAC-SHA-256 test vector 1
    key = bytearray.fromhex('9779d9120642797f1747025d5b22b7ac607cab08e1758f2f3a46c8be1e25c53b8c6a8f58ffefa176')
    message = bytearray.fromhex('b1689c2591eaf3c9e66070f8a77954ffb81749f1b00346f9dfe0b2ee905dcc288baf4a92de3f4001dd9f44'
                                'c468c3d07d6c6ee82faceafc97c2fc0fc0601719d2dcd0aa2aec92d1b0ae933c65eb06a03c9c935c2bad04'
                                '59810241347ab87e9f11adb30415424c6c7f5f22a003b8ab8de54f6ded0e3ab9245fa79568451dfa258e')
    expected_mac_tag = bytearray.fromhex('769f00d3e6a6cc1fb426a14a4f76c6462e6149726e0dee0ec0cf97a16605ac8b')

    mac_tag = hmac(hashes.SHA256(), key, message)

    assert (mac_tag == expected_mac_tag)

    # HMAC-SHA-256 test vector 2
    key = bytearray.fromhex('992868504d2564c4fb47bcbd4ae482d8fb0e8e56d7b81864e61986a0e25682daeb5b50177c095edc9e971da95c'
                            '3210c376e723365ac33d1b4f391817f4c35124')
    message = bytearray.fromhex('ed4f269a8851eb3154771516b27228155200778049b2dc1963f3ac32ba46ea1387cfbb9c39151a2cc406cd'
                                'c13c3c9860a27eb0b7fe8a7201ad11552afd041e33f70e53d97c62f17194b66117028fa9071cc0e04bd92d'
                                'e4972cd54f719010a694e414d4977abed7ca6b90ba612df6c3d467cded85032598a48546804f9cf2ecfe')
    expected_mac_tag = bytearray.fromhex('2f8321f416b9bb249f113b13fc12d70e1668dc332839c10daa5717896cb70ddf')

    mac_tag = hmac(hashes.SHA256(), key, message)

    assert (mac_tag == expected_mac_tag)

    # HMAC-SHA-256 test vector 3
    key = bytearray.fromhex('c09e29071c405d5e820d345a46dbbf1e0f8202e92de3ed3e2d298e43aa4f846866e3b748990946d488c2c1ae5a'
                            '6e99d32790d47d53d205481a497c936bf9ba29fa9c2821919f')
    message = bytearray.fromhex('ea7240529980076d3b028a083ebc4e24efdaa06c9c84d76bf5b2d9fdb842e1038e487f5b30a5e010cddb4f'
                                'cdb01ffc981eb0fcbc7d689207bc90ad36eef9b1ae38487a6dee929f3ff929f3357cb55253b7869a892b28'
                                'f7e5fe386406a2776ed4b21d3b6e1c70cc6485947f27e9a5d8bd820380b9eced8e6b865206541be39fdc')
    expected_mac_tag = bytearray.fromhex('49ae1c4a7a570fde47f7517ab18898b1b991d03cfcf8c45bb3615b5f755da682')

    mac_tag = hmac(hashes.SHA256(), key, message)

    assert (mac_tag == expected_mac_tag)
