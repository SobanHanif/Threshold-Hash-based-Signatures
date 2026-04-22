import hashlib
import secrets
import math

# Hash a value n times with SHA-256
def hash_n_times(value, n):
    hashed = value
    for _ in range(n):
        hashed = hashlib.sha256(hashed).digest()
    return hashed

# Turn the message hash into base-w digits assuming w is a power of 2
def hash_to_base_w_digits(msg_hash, w):
    bits_per_digit = int(math.log2(w))
    total_bits = len(msg_hash) * 8
    num_digits = math.ceil(total_bits / bits_per_digit)

    hash_int = int.from_bytes(msg_hash, byteorder="big")
    digits = []

    for i in range(num_digits):
        shift = total_bits - (i + 1) * bits_per_digit
        if shift >= 0:
            digit = (hash_int >> shift) & (w - 1)
        else:
            digit = (hash_int << (-shift)) & (w - 1)
        digits.append(digit)

    return digits

# Write an integer as base-w using exactly 'length' digits
def int_to_base_w(x, w, length):
    digits = [0] * length
    for i in range(length - 1, -1, -1):
        digits[i] = x % w
        x //= w
    return digits

# Work out how many chains we need
def get_lengths(w, hash_bits=256):
    bits_per_digit = math.log2(w)
    l1 = math.ceil(hash_bits / bits_per_digit)
    l2 = math.floor(math.log(l1 * (w - 1), w)) + 1
    l = l1 + l2
    return l1, l2, l

# Hash message, convert to digits, then add checksum digits
def message_to_digits(message, w):
    msg_hash = hashlib.sha256(message.encode()).digest()

    l1, l2, _ = get_lengths(w)

    msg_digits = hash_to_base_w_digits(msg_hash, w)
    msg_digits = msg_digits[:l1]

    checksum = 0
    for d in msg_digits:
        checksum += (w - 1 - d)

    checksum_digits = int_to_base_w(checksum, w, l2)

    all_digits = []
    for d in msg_digits:
        all_digits.append(d)
    for d in checksum_digits:
        all_digits.append(d)

    return all_digits

# Private key is random starting points
# Public key is end of each hash chain
def generate_keys(w):
    if w < 2 or (w & (w - 1)) != 0:
        print("w must be a power of 2 and at least 2")
        return None, None

    _, _, l = get_lengths(w)

    secret_key = []
    public_key = []

    for _ in range(l):
        sk_part = secrets.token_bytes(32)
        pk_part = hash_n_times(sk_part, w - 1)

        secret_key.append(sk_part)
        public_key.append(pk_part)

    return secret_key, public_key

# Sign by revealing each chain at the needed position
def sign(message, secret_key, w):
    digits = message_to_digits(message, w)

    if len(digits) != len(secret_key):
        print("Secret key length does not match number of chains")
        return None

    signature = []
    for i in range(len(digits)):
        sig_part = hash_n_times(secret_key[i], digits[i])
        signature.append(sig_part)

    return signature

# Verify by hashing forward to the end of the chain
def verify(message, signature, public_key, w):
    digits = message_to_digits(message, w)

    if signature is None:
        return False

    if len(signature) != len(public_key):
        return False

    if len(signature) != len(digits):
        return False

    for i in range(len(digits)):
        candidate = hash_n_times(signature[i], w - 1 - digits[i])
        if candidate != public_key[i]:
            return False

    return True

def main():
    w = 16
    sk, pk = generate_keys(w)

    if sk is None or pk is None:
        return

    msg = input("Message to sign: ").strip()
    if not msg:
        print("Empty message, using demo string.")
        msg = "hello winternitz"

    sig = sign(msg, sk, w)

    ok = verify(msg, sig, pk, w)
    print("verify(signed message):", ok)

    other = msg + "!"
    print("verify(tampered message):", verify(other, sig, pk, w))

if __name__ == "__main__":
    main()