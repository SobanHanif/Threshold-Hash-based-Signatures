import hashlib
import secrets

from merkle import build_merkle, leaf_hash, merkle_auth_path, verify_merkle
import threshold


def _to_bytes(message):
    if isinstance(message, bytes):
        return message
    if isinstance(message, str):
        return message.encode()
    raise TypeError("message must be str or bytes")


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


def sign(message, secret_key):
    # 32 bytes = 256 bits
    if len(secret_key) != 256:
        raise ValueError("secret_key must have length 256")

    for pair in secret_key:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise ValueError("Each secret-key entry must be a pair")

    msg_hash = hashlib.sha256(_to_bytes(message)).digest()
    signature = []
    for i in range(256):
        # Extract bit i from msg_hash
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

        # Verify the signature element hashes to the public key
        if hashlib.sha256(signature[i]).digest() != public_key[i][bit]:
            return False
    return True


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

    from coordinator import Coordinator
    from party import Party

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
