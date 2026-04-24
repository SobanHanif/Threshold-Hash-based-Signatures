"""
Extension 4: hypertrees.
"""

from typing import Callable
import merkle


def _to_bytes(message):
    if isinstance(message, bytes):
        return message
    if isinstance(message, str):
        return message.encode()
    raise TypeError("message must be str or bytes")


class SubTree:
    def __init__(self, keygen_fn: Callable, sign_fn: Callable, hash_fn: Callable, size):
        self._sign_fn = sign_fn
        self._size = size
        self._used = 0
        self._sks = []
        self._pks = []
        leaves = []

        for _ in range(size):
            sk, pk = keygen_fn()
            self._sks.append(sk)
            self._pks.append(pk)
            leaves.append(hash_fn(pk))

        self._levels = merkle.build_merkle(leaves)
        self.root = self._levels[-1][0]

    def exhausted(self):
        return self._used >= self._size

    def sign(self, message):
        if self.exhausted():
            raise RuntimeError("SubTree exhausted")
        idx = self._used
        self._used += 1
        sig = self._sign_fn(self._sks[idx], message)
        path = merkle.merkle_auth_path(self._levels, idx)
        return idx, sig, self._pks[idx], path


class HyperTree:
    def __init__(
        self,
        keygen_fn: Callable,
        sign_fn: Callable,
        verify_fn: Callable,
        hash_fn: Callable,
        subtree_size,
        num_layers,
    ):
        if num_layers < 2:
            raise ValueError("num_layers must be >= 2")

        self._keygen_fn = keygen_fn
        self._sign_fn = sign_fn
        self._verify_fn = verify_fn
        self._hash_fn = hash_fn
        self._subtree_size = subtree_size
        self._num_layers = num_layers

        self._layers = [None] * num_layers

        top_layer_idx = num_layers - 1
        self._layers[top_layer_idx] = SubTree(
            keygen_fn, sign_fn, hash_fn, subtree_size
        )
        self.cpk = self._layers[top_layer_idx].root

        self._link_sigs = [None] * (num_layers - 1)
        self._link_pks = [None] * (num_layers - 1)
        self._link_paths = [None] * (num_layers - 1)
        self._link_indices = [None] * (num_layers - 1)

    def sign(self, message) -> dict:
        # Safety net applied here
        safe_message = _to_bytes(message)

        for d in range(self._num_layers - 2, -1, -1):
            if self._layers[d] is None or self._layers[d].exhausted():
                self._layers[d] = SubTree(
                    self._keygen_fn,
                    self._sign_fn,
                    self._hash_fn,
                    self._subtree_size,
                )

                if self._layers[d + 1].exhausted():
                    raise RuntimeError("need a new master cpk, hypertree exhausted")

                idx, sig, pk, path = self._layers[d + 1].sign(self._layers[d].root)
                self._link_indices[d] = idx
                self._link_sigs[d] = sig
                self._link_pks[d] = pk
                self._link_paths[d] = path

        idx_0, sig_0, pk_0, path_0 = self._layers[0].sign(safe_message)

        return {
            "message": safe_message,  # Stored as safe bytes
            "sigs": [sig_0] + self._link_sigs,
            "pks": [pk_0] + self._link_pks,
            "key_indices": [idx_0] + self._link_indices,
            "auth_paths": [path_0] + self._link_paths,
        }

    def verify(self, signature) -> bool:
        return verify_hyper(signature, self.cpk, self._verify_fn, self._hash_fn)


def verify_hyper(signature: dict, cpk: bytes, verify_fn: Callable, hash_fn: Callable):
    current_msg = _to_bytes(signature["message"])

    for depth in range(len(signature["sigs"])):
        if not verify_fn(
            signature["sigs"][depth], signature["pks"][depth], current_msg
        ):
            return False

        leaf = hash_fn(signature["pks"][depth])
        root = merkle.merkle_root_from_path(
            leaf, signature["key_indices"][depth], signature["auth_paths"][depth]
        )
        current_msg = root

    return current_msg == cpk