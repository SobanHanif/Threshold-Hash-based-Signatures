import hashlib
import secrets

def generate_keys():
    """256 pairs of (0-bit, 1-bit) secrets; public key is SHA-256 of each secret."""
    secret_key = []
    public_key = []
    for _ in range(256):
        pair = [secrets.token_bytes(32), secrets.token_bytes(32)]
        secret_key.append(pair)
        public_key.append(
            [hashlib.sha256(pair[0]).digest(), hashlib.sha256(pair[1]).digest()]
        )
    return secret_key, public_key

def sign(message, secret_key):
    # 32 bytes = 256 bits
    msg_hash = hashlib.sha256(message.encode()).digest()
    signature = []
    for i in range(256):
        # Extract bit i from msg_hash
        byte_index = i // 8
        bit_index = i % 8
        bit = (msg_hash[byte_index] >> bit_index) & 1
        signature.append(secret_key[i][bit])
    return signature

def verify(message, signature, public_key):
    msg_hash = hashlib.sha256(message.encode()).digest()
    for i in range(256):
        byte_index = i // 8
        bit_index = i % 8
        bit = (msg_hash[byte_index] >> bit_index) & 1
        
        # Verify the signature element hashes to the public key
        if hashlib.sha256(signature[i]).digest() != public_key[i][bit]:
            return False
    return True
