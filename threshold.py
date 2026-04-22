import secrets

def xor_bytes(b1, b2):
    if not isinstance(b1, bytes) or not isinstance(b2, bytes):
        raise TypeError("xor_bytes expects bytes inputs")
    if len(b1) != len(b2):
        raise ValueError("Byte strings must have the same length")

    return bytes(x ^ y for x, y in zip(b1, b2))

# Split one secret value into n shares
def split_secret_value(secret_value, n):
    if not isinstance(secret_value, bytes):
        raise TypeError("secret_value must be bytes")
    if n < 1:
        raise ValueError("n must be at least 1")

    if n == 1:
        return [secret_value]

    shares = []
    running_xor = bytes(len(secret_value))

    for _ in range(n - 1):
        share = secrets.token_bytes(len(secret_value))
        shares.append(share)
        running_xor = xor_bytes(running_xor, share)

    shares.append(xor_bytes(secret_value, running_xor))
    return shares

# Split a secret key into n shares
def split_secret_key(secret_key, n):
    if secret_key is None:
        raise ValueError("secret_key cannot be None")
    if n < 1:
        raise ValueError("n must be at least 1")
    if len(secret_key) == 0:
        raise ValueError("secret_key cannot be empty")

    shares = [[] for _ in range(n)]

    for pair in secret_key:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise ValueError("Each secret-key entry must be a pair")

        p0, p1 = pair
        split0 = split_secret_value(p0, n)
        split1 = split_secret_value(p1, n)

        for j in range(n):
            shares[j].append([split0[j], split1[j]])

    return shares

# Reconstruct the original secret key from n shares
def reconstruct_secret_key(shares):
    if not shares:
        raise ValueError("shares cannot be empty")

    key_len = len(shares[0])
    for share in shares:
        if len(share) != key_len:
            raise ValueError("All shares must have the same Lamport key length")

    secret_key = []
    for i in range(key_len):
        p0 = shares[0][i][0]
        p1 = shares[0][i][1]

        for j in range(1, len(shares)):
            p0 = xor_bytes(p0, shares[j][i][0])
            p1 = xor_bytes(p1, shares[j][i][1])

        secret_key.append([p0, p1])

    return secret_key

# Combine n signature shares into a single signature
def combine_signatures(sig_shares):
    if not sig_shares:
        raise ValueError("sig_shares cannot be empty")

    res = []
    n = len(sig_shares)
    sig_len = len(sig_shares[0])

    for share in sig_shares:
        if len(share) != sig_len:
            raise ValueError("All signature shares must have the same length")

    for i in range(sig_len):
        val = sig_shares[0][i]
        for j in range(1, n):
            val = xor_bytes(val, sig_shares[j][i])

        res.append(val)
    return res
