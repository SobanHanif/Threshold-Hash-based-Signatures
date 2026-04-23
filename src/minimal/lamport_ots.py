import hashlib


def _to_bytes(message):
    if isinstance(message, bytes):
        return message
    if isinstance(message, str):
        return message.encode()
    raise TypeError("message must be str or bytes")


def sign(message, secret_key):
    if len(secret_key) != 256:
        raise ValueError("secret_key must have length 256")

    for pair in secret_key:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise ValueError("Each secret-key entry must be a pair")

    msg_hash = hashlib.sha256(_to_bytes(message)).digest()
    signature = []
    for i in range(256):
        byte_index = i // 8
        bit_index = i % 8
        bit = (msg_hash[byte_index] >> bit_index) & 1
        signature.append(secret_key[i][bit])
    return signature


def verify(message, signature, public_key):
    if len(signature) != 256 or len(public_key) != 256:
        return False

    for i in range(256):
        if not isinstance(signature[i], bytes):
            return False
        if not isinstance(public_key[i], (list, tuple)) or len(public_key[i]) != 2:
            return False
        if not isinstance(public_key[i][0], bytes) or not isinstance(public_key[i][1], bytes):
            return False

    msg_hash = hashlib.sha256(_to_bytes(message)).digest()
    for i in range(256):
        byte_index = i // 8
        bit_index = i % 8
        bit = (msg_hash[byte_index] >> bit_index) & 1
        if hashlib.sha256(signature[i]).digest() != public_key[i][bit]:
            return False
    return True
