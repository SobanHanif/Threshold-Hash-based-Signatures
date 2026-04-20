import secrets
import hashlib
import lamport
from typing import Callable


"""Math notes:
  In a 1-indexed array representing a complete tree
  child nodes are at 2i, 2i
"""

class MerkleTree:
    # helper methods
    def _hash_pair(self, left: bytes, right: bytes):
        return self.hash_fn(left + right)


    def __init__(self, leaves: list[bytes], hash_fn: Callable[[bytes], bytes] = hashlib.sha256):
        """
        Constructor which takes in a list of all bytes forming the initial bitstring, and an optional hash function
        """
        if len(leaves) == 0:
            raise ValueError("Need at least one leaf")
        # In future implementations, any hanging leaf nodes can be saved by duplicating the child to have 2 identical children
        if len(leaves) & (len(leaves) - 1) != 0:
            raise ValueError("Number of leaves must be a 2^n")
        # MEMBERS
        self.hash_fn = hash_fn
        self.num_leaves = len(leaves)
        # equivalent to log_2{length}

        self.depth = len(leaves).bit_length() - 1
        self.actual_count = len(leaves)
        # As Merkle Trees are full, we represent the tree as a flat array.
        # Index 1 = root, indices 2..3 = second level, etc.
        # Leaves start at index num_leaves
        self.tree = [None] * (2 * self.num_leaves)
        for i in range(self.num_leaves):
            if i < self.actual_count:
                self.tree[self.num_leaves + i] = self.hash_fn(leaves[i])
            else:
                # padding: dupe the last valid leaf hash/null
                self.tree[self.num_leaves + i] = self.tree[self.num_leaves + self.actual_count - 1]

        for i in range(self.num_leaves - 1, 0, -1):
            self.tree[i] = self._hash_pair(self.tree[2 * i], self.tree[2 * i + 1])

    @property
    def root(self) -> bytes:
        """Returns the root/initial node of the tree (CompositePUblicKey in the paper)"""
        return self.tree[1]

    def make_path(self, key_id: int) -> list[bytes]:
        """
        Produce the authentication PATH for the leaf at key_id (noninclusive of root)
        """
        if key_id < 0 or key_id >= self.num_leaves:
            raise ValueError(f"key_id must be in range [0, {self.num_leaves})")

        path = []
        # Start at the leaf's position in the flat array
        i = self.num_leaves + key_id

        while i > 1:
            # Get the sibling: even => i+1; odd => i-1
            if i % 2 == 0:
                sibling = self.tree[i + 1]
            else:
                sibling = self.tree[i - 1]
            path.append(sibling)
            i //= 2

        return path

    def verify(self, key_id: int, leaf_value: bytes, path: list[bytes]) -> bool:
        """
        verify that leaf_value at key_id is in the tree by recomputing the root
        using the provided PATH verification and checking it matches the stored root
        """
        # Start by hashing the raw leaf value 
        current = self.hash_fn(leaf_value)

        i = self.num_leaves + key_id

        for sibling in path:
            if i % 2 == 0:
                # left child is hash(curr, sibling)
                current = self._hash_pair(current, sibling)
            else:
                current = self._hash_pair(sibling, current)

            i //= 2

        return current == self.root