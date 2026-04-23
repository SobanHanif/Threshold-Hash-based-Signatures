import hashlib
import secrets

from coordinator import Coordinator
from merkle import build_merkle, leaf_hash, merkle_auth_path, verify_merkle
from lamport_ots import sign, verify
from party import Party
import threshold


def generate_keys():
    secret_key = []
    public_key = []
    for _ in range(256):
        pair = [secrets.token_bytes(32), secrets.token_bytes(32)]
        secret_key.append(pair)
        public_key.append(
            [hashlib.sha256(pair[0]).digest(), hashlib.sha256(pair[1]).digest()]
        )
    return secret_key, public_key
def merkle_keygen(n_parties, n_leaves):
    if n_parties < 1:
        raise ValueError("n_parties must be at least 1")
    if n_leaves < 1:
        raise ValueError("n_leaves must be at least 1")

    leaf_pks = []
    party_shares = {party_id: [] for party_id in range(n_parties)}

    # One Lamport keypair per leaf
    for _ in range(n_leaves):
        sk, pk = generate_keys()
        shares = threshold.split_secret_key(sk, n_parties)

        leaf_pks.append(pk)
        for party_id in range(n_parties):
            party_shares[party_id].append(shares[party_id])

    leaves = [leaf_hash(pk) for pk in leaf_pks]
    tree = build_merkle(leaves)
    root = tree[-1][0]

    return {
        "n_parties": n_parties,
        "n_leaves": n_leaves,
        "root": root,
        "tree": tree,
        "leaf_public_keys": leaf_pks,
        "party_shares": party_shares,
        "used_leaves": set(),
    }


def merkle_sign(message, leaf_idx, state):
    if leaf_idx < 0 or leaf_idx >= state["n_leaves"]:
        raise ValueError(f"leaf_idx {leaf_idx} out of range")
    if leaf_idx in state["used_leaves"]:
        raise RuntimeError(f"leaf {leaf_idx} already used")

    leaf_pk = state["leaf_public_keys"][leaf_idx]
    parties = []

    # Build one Party object per share for this leaf
    for party_id in range(state["n_parties"]):
        sk_share = state["party_shares"][party_id][leaf_idx]
        parties.append(Party(party_id=party_id, sk_share=sk_share))

    coordinator = Coordinator(leaf_pk, parties)
    signature = coordinator.sign(message)
    auth_path = merkle_auth_path(state["tree"], leaf_idx)
    state["used_leaves"].add(leaf_idx)

    return {
        "leaf_idx": leaf_idx,
        "leaf_pk": leaf_pk,
        "signature": signature,
        "auth_path": auth_path,
    }


def merkle_verify(message, sig, root):
    # First verify the Lamport signature itself
    if not verify(message, sig["signature"], sig["leaf_pk"]):
        return False

    # Then verify the Merkle path for that leaf
    leaf = leaf_hash(sig["leaf_pk"])
    return verify_merkle(leaf, sig["leaf_idx"], sig["auth_path"], root)
