from cryptography.hazmat.primitives import hashes, hmac


chosen_hash = hashes.SHA256()


def create_hmac(key: bytes, msg: bytes):
    if not isinstance(msg, bytes):
        print(msg)
        raise TypeError("type of msg is not bytes")
    h = hmac.HMAC(key, chosen_hash)
    h.update(msg)
    return h.finalize()


def verify_hmac(key: bytes, msg: bytes, tag: bytes):
    h = create_hmac(key, msg)
    if len(h) != len(tag):
        return False
    result = 0
    for x, y in zip(h, tag):
        result |= x ^ y
    return result == 0
