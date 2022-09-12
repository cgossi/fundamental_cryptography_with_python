from cryptography.hazmat.primitives import hashes


def hash_for_algorithm(algorithm, data):
    hash_object = hashes.Hash(algorithm)
    hash_object.update(data)
    return hash_object.finalize()


if __name__ == "__main__":

    data = b'Fundamentals of Cryptographic Hash Functions'
    print(f"Binary data: {data}")

    # MD5 - Deprecated!
    # md5 = hashes.Hash(hashes.MD5())
    # md5.update(data)
    # hash_value = md5.finalize()
    md5_hash = hash_for_algorithm(hashes.MD5(), data)
    print(f"MD5 hash ({len(md5_hash * 8)} bits): {md5_hash.hex()}")

    # SHA-1 - Deprecated!
    sha1_hash = hash_for_algorithm(hashes.SHA1(), data)
    print(f"SHA-1 hash ({len(sha1_hash * 8)} bits): {sha1_hash.hex()}")

    # SHA-256
    sha_256_hash = hash_for_algorithm(hashes.SHA256(), data)
    print(f"SHA-256 hash ({len(sha_256_hash * 8)} bits): {sha_256_hash.hex()}")

    # SHA-3-512
    sha_3_512_hash = hash_for_algorithm(hashes.SHA3_512(), data)
    print(f"SHA-3-512 hash ({len(sha_3_512_hash * 8)} bits): {sha_3_512_hash.hex()}")

    # MD5 Collision
    with open("md5_collision_image_1.png", "rb") as f:
        image_1_bytes = f.read()

    with open("md5_collision_image_2.png", "rb") as f:
        image_2_bytes = f.read()

    image_1_md5_hash = hash_for_algorithm(hashes.MD5(), image_1_bytes)
    image_2_md5_hash = hash_for_algorithm(hashes.MD5(), image_2_bytes)

    assert (image_1_bytes != image_2_bytes)
    assert (image_1_md5_hash == image_2_md5_hash)

    # SHA-1 Collision
    with open("shattered_1.pdf", "rb") as f:
        pdf_1_bytes = f.read()

    with open("shattered_2.pdf", "rb") as f:
        pdf_2_bytes = f.read()

    pdf_1_sha1_hash = hash_for_algorithm(hashes.SHA1(), pdf_1_bytes)
    pdf_2_sha1_hash = hash_for_algorithm(hashes.SHA1(), pdf_2_bytes)

    assert (pdf_1_bytes != pdf_2_bytes)
    assert (pdf_1_sha1_hash == pdf_2_sha1_hash)

    # Check SHA-256 doesn't collide on MD5 collision images
    image_1_sha_256_hash = hash_for_algorithm(hashes.SHA256(), image_1_bytes)
    image_2_sha_256_hash = hash_for_algorithm(hashes.SHA256(), image_2_bytes)

    assert (image_1_bytes != image_2_bytes)
    assert (image_1_sha_256_hash != image_2_sha_256_hash)

    # Check SHA-256 doesn't collide on shattered.io
    pdf_1_sha_256_hash = hash_for_algorithm(hashes.SHA256(), pdf_1_bytes)
    pdf_2_sha_256_hash = hash_for_algorithm(hashes.SHA256(), pdf_2_bytes)

    assert (pdf_1_bytes != pdf_2_bytes)
    assert (pdf_1_sha_256_hash != pdf_2_sha_256_hash)
