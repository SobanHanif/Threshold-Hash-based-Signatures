import secrets

def xor_bytes(b1, b2):
    res = bytearray()
    for i in range(len(b1)):
        x, y = b1[i], b2[i]
        res.append(x ^ y)

    return res

# Split a secret key into n shares
def split_secret_key(secret_key, n):
    shares = []
    for _ in range(n - 1):
        share = []
        for i in range(256):
            pair = [secrets.token_bytes(32), secrets.token_bytes(32)]
            share.append(pair)
        shares.append(share)
    
    last_share = []
    for i in range(256):
        p0, p1 = secret_key[i][0], secret_key[i][1]
        for j in range(n - 1):
            p0 = xor_bytes(p0, shares[j][i][0])
            p1 = xor_bytes(p1, shares[j][i][1])
        last_share.append([p0, p1])
    shares.append(last_share)
    
    return shares

# Combine n signature shares into a single signature
def combine_signatures(sig_shares):
    res = []
    n = len(sig_shares)
    for i in range(256):
        val = sig_shares[0][i]
        for j in range(1, n):
            val = xor_bytes(val, sig_shares[j][i])

        res.append(val)
    return res
