import hashlib
import hmac
import secrets

import lamport
from merkle import build_merkle, leaf_hash
import threshold

PRF_KEY_SIZE = 32


def derive_share(prf_key, party_id, leaf_idx, pair_idx, half):
    if not isinstance(prf_key, bytes) or len(prf_key) != PRF_KEY_SIZE:
        raise ValueError("prf_key must be 32 bytes")
    if half not in (0, 1):
        raise ValueError("half must be 0 or 1")

    data = f"{party_id}:{leaf_idx}:{pair_idx}:{half}".encode()
    return hmac.new(prf_key, b"prf-share|" + data, hashlib.sha256).digest()


def make_server_share(secret_value, derived_shares):
    running_xor = bytes(len(secret_value))
    for share in derived_shares:
        running_xor = threshold.xor_bytes(running_xor, share)
    return threshold.xor_bytes(secret_value, running_xor)


def reconstruct_leaf_secret(state, leaf_idx):
    shares = [
        state["party_shares"][party_id][leaf_idx]
        for party_id in range(state["n_parties"])
    ]
    return threshold.reconstruct_secret_key(shares)


def merkle_keygen_prf(
    n_parties,
    n_leaves,
    server_party_id=0,
    party_prf_keys=None,
):
    if n_parties < 1:
        raise ValueError("n_parties must be at least 1")
    if n_leaves < 1:
        raise ValueError("n_leaves must be at least 1")
    if server_party_id < 0 or server_party_id >= n_parties:
        raise ValueError("server_party_id out of range")

    other_ids = [party_id for party_id in range(n_parties) if party_id != server_party_id]
    if party_prf_keys is None:
        party_prf_keys = {
            party_id: secrets.token_bytes(PRF_KEY_SIZE) for party_id in other_ids
        }
    else:
        if not isinstance(party_prf_keys, dict):
            raise TypeError("party_prf_keys must be a dict keyed by party id")
        for party_id in other_ids:
            prf_key = party_prf_keys.get(party_id)
            if not isinstance(prf_key, bytes) or len(prf_key) != PRF_KEY_SIZE:
                raise ValueError(f"party {party_id} must have a 32-byte PRF key")

    leaf_secret_keys = []
    leaf_public_keys = []
    party_shares = {party_id: [] for party_id in range(n_parties)}

    for leaf_idx in range(n_leaves):
        sk, pk = lamport.generate_keys()
        shares_for_leaf = {party_id: [] for party_id in range(n_parties)}

        for pair_idx, pair in enumerate(sk):
            left, right = pair
            derived_left = []
            derived_right = []

            for party_id in other_ids:
                prf_key = party_prf_keys[party_id]
                left_share = derive_share(
                    prf_key, party_id, leaf_idx, pair_idx, 0
                )
                right_share = derive_share(
                    prf_key, party_id, leaf_idx, pair_idx, 1
                )
                shares_for_leaf[party_id].append([left_share, right_share])
                derived_left.append(left_share)
                derived_right.append(right_share)

            server_left = make_server_share(left, derived_left)
            server_right = make_server_share(right, derived_right)
            shares_for_leaf[server_party_id].append([server_left, server_right])

        leaf_secret_keys.append(sk)
        leaf_public_keys.append(pk)
        for party_id in range(n_parties):
            party_shares[party_id].append(shares_for_leaf[party_id])

    leaves = [leaf_hash(pk) for pk in leaf_public_keys]
    tree = build_merkle(leaves)
    root = tree[-1][0]

    return {
        "variant": "prf_merkle_lamport",
        "n_parties": n_parties,
        "n_leaves": n_leaves,
        "server_party_id": server_party_id,
        "party_prf_keys": party_prf_keys,
        "leaf_secret_keys": leaf_secret_keys,
        "root": root,
        "tree": tree,
        "leaf_public_keys": leaf_public_keys,
        "party_shares": party_shares,
        "used_leaves": set(),
    }
