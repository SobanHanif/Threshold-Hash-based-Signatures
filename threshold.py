import hashlib
import secrets
from itertools import combinations

from winternitz import sign as wots_sign
from winternitz import generate_keys as wots_keygen
from winternitz import verify as wots_verify


def xor_bytes(b1, b2):
    res = bytearray()
    for i in range(len(b1)):
        x, y = b1[i], b2[i]
        res.append(x ^ y)

    return res


# split wots secret key (l 32 byte chain starting points) into n XOR shares
def split_secret_key(secret_key, n):
    l = len(secret_key)
    shares = []
    for _ in range(n - 1):
        share = [secrets.token_bytes(32) for _ in range(l)]
        shares.append(share)

    last_share = []
    for i in range(l):
        acc = secret_key[i]
        for j in range(n - 1):
            acc = xor_bytes(acc, shares[j][i])
        last_share.append(bytes(acc))
    shares.append(last_share)

    return shares


# combines n signature shares into a single WOTS signature
# 1. XOR all shares by element -> WOTS SK
# 2. apply WOTS sign with the reconstructed sk and the message sent
def combine_signatures(sig_shares, message, w):
    n = len(sig_shares)
    l = len(sig_shares[0])

    reconstructed_sk = []
    for i in range(l):
        acc = sig_shares[0][i]
        for j in range(1, n):
            acc = xor_bytes(acc, sig_shares[j][i])
        reconstructed_sk.append(bytes(acc))

    return wots_sign(message, reconstructed_sk, w)


# extension 1: k-of-n via k-of-k subtrees
# for every k-subset of the n parties we run the existing k-of-k
# WOTS (new generated WOTS key pair, sk split into k XOR shares)
# leaves of merkle tree = H(wots_pk of each subset)
# the root of merkle tree is the public key of all parties
# a signature has -> subset index, the k-of-k WOTS signature, the subsets WOTS pk, and merkle path to root


def _leaf_hash(wots_pk):
    # wots_pk is a list of 32 byte hash chain final values
    return hashlib.sha256(b"".join(wots_pk)).digest()


def _build_merkle(leaves):
    # binary merkle tree w/ odd nodes duplicating the last sibling
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


def kofn_keygen(n, k, w):
    # sort k subsets in lexigraphic order 
    subsets = list(combinations(range(n), k))

    # for each subset -> new WOTS key pair + k XOR shares
    subset_pks = []
    subset_shares = []  # subset_shares[s][pos] = share held by subset[s][pos]
    for _ in subsets:
        sk, pk = wots_keygen(w)
        shares = split_secret_key(sk, k)
        subset_pks.append(pk)
        subset_shares.append(shares)

    # merkle tree over subsets pks
    leaves = [_leaf_hash(pk) for pk in subset_pks]
    tree = _build_merkle(leaves)
    root = tree[-1][0]

    # distribute shares to parties -> party_shares[party_id][subset_idx] = their share
    party_shares = {p: {} for p in range(n)}
    for s_idx, subset in enumerate(subsets):
        for pos, party_id in enumerate(subset):
            party_shares[party_id][s_idx] = subset_shares[s_idx][pos]

    # groups the dealers data used by sign & verify
    state = {
        "n": n,
        "k": k,
        "w": w,
        "root": root,
        "tree": tree,
        "subsets": subsets,
        "subset_pks": subset_pks,
        "party_shares": party_shares,
    }
    return state

# create k-of-n signature ONCE subset of k parties chosen
def kofn_sign(selected_parties, message, state):
    n, k, w = state["n"], state["k"], state["w"]

    subset_tuple = tuple(sorted(selected_parties))
    if len(set(subset_tuple)) != k:
        raise ValueError(f"need EXACTLY {k} distinct parties but received {selected_parties}")
    for p in subset_tuple:
        if p < 0 or p >= n:
            raise ValueError(f"party id {p} out of range [0,{n}]")

    try:
        s_idx = state["subsets"].index(subset_tuple)
    except ValueError:
        raise ValueError(f"subset {subset_tuple} not in enumeration")

    # each selected party contributes its share for this specific subset
    sig_shares = []
    for p in subset_tuple:
        share = state["party_shares"][p].get(s_idx)
        if share is None:
            raise RuntimeError(f"party {p} is missing its share for subset {s_idx}")
        sig_shares.append(share)

    wots_sig = combine_signatures(sig_shares, message, w)
    auth_path = _merkle_auth_path(state["tree"], s_idx)

    return {
        "subset_idx": s_idx,
        "subset_pk": state["subset_pks"][s_idx],
        "wots_sig": wots_sig,
        "auth_path": auth_path,
    }

# checks :
# 1. indices are in bounds
# 2. checks if WOTS signature is valid on message under THAT subsets pk
# 3. walks auth path (merkle path) to create root and compare to known merkle root
def kofn_verify(message, sig, root, n, k, w):
    subsets = list(combinations(range(n), k))
    s_idx = sig["subset_idx"]
    if s_idx < 0 or s_idx >= len(subsets):
        return False

    if not wots_verify(message, sig["wots_sig"], sig["subset_pk"], w):
        return False

    leaf = _leaf_hash(sig["subset_pk"])
    return _verify_merkle(leaf, s_idx, sig["auth_path"], root)
