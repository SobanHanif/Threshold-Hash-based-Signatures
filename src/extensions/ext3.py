"""
Extension 3: batch signing using an inner Merkle tree for messages
and an outer Merkle tree over public keys.
"""

import hashlib
import merkle


def _to_bytes(message):
    if isinstance(message, bytes):
        return message
    if isinstance(message, str):
        return message.encode()
    raise TypeError("message must be str or bytes")


class BatchHandler:
    def __init__(self, batch_size: int, signature_fn, pks: list):
        outer_leaves = [merkle.leaf_hash(pk) for pk in pks]
        outer_tree_levels = merkle.build_merkle(outer_leaves)

        self.batch_size = batch_size
        self.outer_levels = outer_tree_levels
        self.outer_root = outer_tree_levels[-1][0]
        self.pks = pks
        self.signature_fn = signature_fn

        self.buffer = []
        self.current_key_id = 0
        self.completed_batches = []

    def addMessage(self, message):
        self.buffer.append(message)
        if len(self.buffer) == self.batch_size:
            self._reset_buffer()

    # accounting for the edge case of flushing required before fulfillment
    def premature_reset(self):
        if len(self.buffer) == 0: return
        self._reset_buffer()


    def _reset_buffer(self):
        if self.current_key_id >= len(self.pks):
            raise RuntimeError("all keypairs exhausted!")

        messages = list(self.buffer)
        key_id = self.current_key_id
        inner_levels, inner_root = self._build_inner_tree(messages)
        curr_sig = self.signature_fn(inner_root, key_id)
        outer_path = merkle.merkle_auth_path(self.outer_levels, key_id)

        self.completed_batches.append(
            {
                "key_id": key_id,
                "messages": messages,
                "inner_levels": inner_levels,
                "inner_root": inner_root,
                "signature": curr_sig,
                "pk": self.pks[key_id],
                "outer_path": outer_path,
            }
        )

        self.current_key_id += 1
        self.buffer = []

    def get_proof(self, batch_index: int, message_index: int) -> dict:
        batch = self.completed_batches[batch_index]
        inner_path = merkle.merkle_auth_path(batch["inner_levels"], message_index)

        return {
            "message": batch["messages"][message_index],
            "message_index": message_index,
            "inner_path": inner_path,
            "inner_root": batch["inner_root"],
            "key_id": batch["key_id"],
            "signature": batch["signature"],
            "pk": batch["pk"],
            "outer_path": batch["outer_path"],
        }

    def _build_inner_tree(self, messages: list):
        # Safety net applied here
        leaves = [hashlib.sha256(_to_bytes(message)).digest() for message in messages]
        levels = merkle.build_merkle(leaves)
        root = levels[-1][0]
        return levels, root

    def batch_verify(self, proof: dict, outer_root, verify_fn) -> bool:
        message = proof["message"]
        message_index = proof["message_index"]
        inner_path = proof["inner_path"]
        inner_root = proof["inner_root"]
        key_id = proof["key_id"]
        signature = proof["signature"]
        pk = proof["pk"]
        outer_path = proof["outer_path"]

        inner_leaf = hashlib.sha256(_to_bytes(message)).digest()
        
        if not merkle.verify_merkle(inner_leaf, message_index, inner_path, inner_root):
            return False

        if not verify_fn(inner_root, signature, pk):
            return False

        outer_leaf = merkle.leaf_hash(pk)
        return merkle.verify_merkle(outer_leaf, key_id, outer_path, outer_root)