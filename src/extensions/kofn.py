import math
from itertools import combinations

from merkle import build_merkle, merkle_auth_path, verify_merkle
from threshold import split_secret_key, xor_bytes


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


def kofn_keygen(n, k, ots):
    # k subsets into lexgraphic order
    subsets = list(combinations(range(n), k))
    # optimisation 1: precompute subset lookup so signing does O(1) lookup
    subset_to_idx = {subset: idx for idx, subset in enumerate(subsets)}

    subset_pks = []
    subset_shares = []  # subset_shares[s][pos] = share held by subset[s][pos]
    for _ in subsets:
        sk, pk = ots.keygen()
        flat_sk = ots.flatten_sk(sk)
        shares = split_secret_key(flat_sk, k, ots.share_element_size())
        subset_pks.append(pk)
        subset_shares.append(shares)

    leaves = [ots.leaf_hash(pk) for pk in subset_pks]
    tree = build_merkle(leaves)
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
        "subset_to_idx": subset_to_idx,
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
        # old version:
        # s_idx = state["subsets"].index(subset_tuple)
        # optimisation 1:
        s_idx = state["subset_to_idx"][subset_tuple]
    except KeyError:
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
    auth_path = merkle_auth_path(state["tree"], s_idx)
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
    return verify_merkle(leaf, s_idx, sig["auth_path"], root)
