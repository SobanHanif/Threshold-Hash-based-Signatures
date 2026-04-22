import hashlib
import math
import secrets
from itertools import combinations


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
def split_secret_key(secret_key, n, element_size=32):
    if secret_key is None:
        raise ValueError("secret_key cannot be None")
    if n < 1:
        raise ValueError("n must be at least 1")
    if len(secret_key) == 0:
        raise ValueError("secret_key cannot be empty")

    shares = [[] for _ in range(n)]
    first = secret_key[0]

    # Lamport-style secret key: [(s0, s1), ...]
    if isinstance(first, (list, tuple)) and len(first) == 2:
        for pair in secret_key:
            if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                raise ValueError("Each secret-key entry must be a pair")

            p0, p1 = pair
            split0 = split_secret_value(p0, n)
            split1 = split_secret_value(p1, n)

            for j in range(n):
                shares[j].append([split0[j], split1[j]])

        return shares

    # Flat OTS secret key: [x0, x1, ...]
    for value in secret_key:
        if not isinstance(value, bytes):
            raise ValueError("Each flat secret-key entry must be bytes")
        if len(value) != element_size:
            raise ValueError("Secret-key element has unexpected size")

        split_value = split_secret_value(value, n)
        for j in range(n):
            shares[j].append(split_value[j])

    return shares


# Reconstruct the original Lamport secret key from n shares
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


# Combine n signature shares into a single Lamport signature
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


# combines n signature shares into a single OTS signature
# 1. XOR all shares by element -> flattened SK
# 2. give ots class which unflattens if needed and signs
def ots_combine_signature(sig_shares, message, ots):
    if not sig_shares:
        raise ValueError("sig_shares cannot be empty")

    n = len(sig_shares)
    sig_len = len(sig_shares[0])

    for share in sig_shares:
        if len(share) != sig_len:
            raise ValueError("All signature shares must have the same length")

    reconstructed_flat = []
    for i in range(sig_len):
        acc = sig_shares[0][i]
        for j in range(1, n):
            acc = xor_bytes(acc, sig_shares[j][i])
        reconstructed_flat.append(acc)

    return ots.sign(message, ots.unflatten_sk(reconstructed_flat))


# extension 1: k-of-n via k-of-k subtrees
# for every k-subset of the n parties we run the k-of-k construction
# (new generated OTS keypair, SK split into k XOR shares). 
# root has combined public key


def _build_merkle(leaves):
    # binary merkle tree with odd nodes duplicating the last sibling.
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        prev = levels[-1]
        cur = []
        for i in range(0, len(prev), 2):
            left = prev[i]
            right = prev[i + 1] if i + 1 < len(prev) else prev[i]
            cur.append(hashlib.sha256(left + right).digest())
        levels.append(cur)
    return levels


def _merkle_auth_path(levels, index):
    path = []
    idx = index
    for level in levels[:-1]:
        if idx % 2 == 0:
            sibling_idx = idx + 1 if idx + 1 < len(level) else idx
        else:
            sibling_idx = idx - 1
        path.append(level[sibling_idx])
        idx //= 2
    return path


def _verify_merkle(leaf, index, path, root):
    cur = leaf
    idx = index
    for sibling in path:
        if idx % 2 == 0:
            cur = hashlib.sha256(cur + sibling).digest()
        else:
            cur = hashlib.sha256(sibling + cur).digest()
        idx //= 2
    return cur == root


def kofn_keygen(n, k, ots):
    # k subsets into lexgraphic order
    subsets = list(combinations(range(n), k))

    subset_pks = []
    subset_shares = []  # subset_shares[s][pos] = share held by subset[s][pos]
    for _ in subsets:
        sk, pk = ots.keygen()
        flat_sk = ots.flatten_sk(sk)
        shares = split_secret_key(flat_sk, k, ots.share_element_size())
        subset_pks.append(pk)
        subset_shares.append(shares)

    leaves = [ots.leaf_hash(pk) for pk in subset_pks]
    tree = _build_merkle(leaves)
    root = tree[-1][0]

    # party_shares[party_id][subset_idx] = selected partys share for selected subset
    party_shares = {p: {} for p in range(n)}
    for s_idx, subset in enumerate(subsets):
        for pos, party_id in enumerate(subset):
            party_shares[party_id][s_idx] = subset_shares[s_idx][pos]

    return {
        "n": n,
        "k": k,
        "ots": ots,
        "root": root,
        "tree": tree,
        "subsets": subsets,
        "subset_pks": subset_pks,
        "party_shares": party_shares,
        # each enumerated subset holds exactly one ots keypair -> can only sign one message as reusing it leaks sk
        "used_subsets": set(),
    }


def kofn_sign(selected_parties, message, state):
    n, k, ots = state["n"], state["k"], state["ots"]

    subset_tuple = tuple(sorted(selected_parties))
    if len(set(subset_tuple)) != k:
        raise ValueError(
            f"need EXACTLY {k} distinct parties but received {selected_parties}"
        )
    for p in subset_tuple:
        if p < 0 or p >= n:
            raise ValueError(f"party id {p} out of range [0,{n})")

    try:
        s_idx = state["subsets"].index(subset_tuple)
    except ValueError:
        raise ValueError(f"subset {subset_tuple} not in enumeration")

    if s_idx in state["used_subsets"]:
        raise RuntimeError(
            f"subset {subset_tuple} already signed once, using this OTS again will leak the sk"
        )

    sig_shares = []
    for p in subset_tuple:
        share = state["party_shares"][p].get(s_idx)
        if share is None:
            raise RuntimeError(f"party {p} is missing its share for subset {s_idx}")
        sig_shares.append(share)

    ots_sig = ots_combine_signature(sig_shares, message, ots)
    auth_path = _merkle_auth_path(state["tree"], s_idx)
    state["used_subsets"].add(s_idx)

    return {
        "subset_idx": s_idx,
        "subset_pk": state["subset_pks"][s_idx],
        "ots_sig": ots_sig,
        "auth_path": auth_path,
    }


# verifier:
# 1 bounds check subset_idx
# 2 verify OTS signature on message under the signatures subset_pk
# 3 leaf = ots.leaf_hash(subset_pk), walk from this up merkle path to root and compare
def kofn_verify(message, sig, root, n, k, ots):
    s_idx = sig["subset_idx"]
    if s_idx < 0 or s_idx >= math.comb(n, k):
        return False

    if not ots.verify(message, sig["ots_sig"], sig["subset_pk"]):
        return False

    leaf = ots.leaf_hash(sig["subset_pk"])
    return _verify_merkle(leaf, s_idx, sig["auth_path"], root)
