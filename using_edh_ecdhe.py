from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def use_edh():

    # Generate public DH parameters
    dh_parameters = dh.generate_parameters(generator=2, key_size=512) # 512 only for demo, at least 2048 in production!
    g = dh_parameters.parameter_numbers().g
    p = dh_parameters.parameter_numbers().p

    # Generate public-private key of Alice
    private_key_a = dh_parameters.generate_private_key()
    public_key_a = private_key_a.public_key()

    x = private_key_a.private_numbers().x
    a = public_key_a.public_numbers().y
    assert (a == pow(g, x, p))

    # Generate public-private key of Bob
    private_key_b = dh_parameters.generate_private_key()
    public_key_b = private_key_b.public_key()

    y = private_key_b.private_numbers().x
    b = public_key_b.public_numbers().y
    assert (b == pow(g, y, p))

    # Generate shared key for Alice
    shared_key_alice = private_key_a.exchange(public_key_b)

    k_a = int.from_bytes(shared_key_alice, byteorder="big")
    assert (k_a == pow(b, x, p))

    # Generate shared key for Bob
    shared_key_bob = private_key_b.exchange(public_key_a)

    k_b = int.from_bytes(shared_key_bob, byteorder="big")
    assert (k_b == pow(a, y, p))

    # Verify Alice and Bob arrived at the same shared key
    assert (shared_key_alice == shared_key_bob)


def use_ecdhe():

    # X25519, which is ECDHE working against Curve25519

    # Generate public-private key of Alice
    private_key_a = X25519PrivateKey.generate()
    public_key_a = private_key_a.public_key()

    # Generate public-private key of Bob
    private_key_b = X25519PrivateKey.generate()
    public_key_b = private_key_b.public_key()

    # Generate shared key for Alice
    shared_key_a = private_key_a.exchange(public_key_b)

    # Generate shared key for Bob
    shared_key_b = private_key_b.exchange(public_key_a)

    # Verify Alice and Bob arrived at the same shared key
    assert (shared_key_a == shared_key_b)


if __name__ == "__main__":

    use_edh()
    use_ecdhe()
