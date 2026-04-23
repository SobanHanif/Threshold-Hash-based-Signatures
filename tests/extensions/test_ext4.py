import hashlib
import unittest

from tests import _path
import ext4
import lamport
import merkle
import winternitz


def lamport_hash_pk(pk):
    parts = [p for pair in pk for p in pair]
    return hashlib.sha256(b"".join(parts)).digest()


def to_wots_message(message):
    if isinstance(message, bytes):
        return message.hex()
    return message


class TestExt4HyperTree(unittest.TestCase):
    def test_hypertree_lamport(self):
        ht = ext4.HyperTree(
            keygen_fn=lamport.generate_keys,
            sign_fn=lambda sk, msg: lamport.sign(msg, sk),
            verify_fn=lambda sig, pk, msg: lamport.verify(msg, sig, pk),
            hash_fn=lamport_hash_pk,
            subtree_size=2,
            num_layers=2,
        )

        sig = ht.sign("Lamport purely string message")
        self.assertTrue(ht.verify(sig))

    def test_hypertree_winternitz(self):
        w = 16
        ht = ext4.HyperTree(
            keygen_fn=lambda: winternitz.generate_keys(w),
            sign_fn=lambda sk, msg: winternitz.sign(to_wots_message(msg), sk, w),
            verify_fn=lambda sig, pk, msg: winternitz.verify(to_wots_message(msg), sig, pk, w),
            hash_fn=merkle.leaf_hash,
            subtree_size=2,
            num_layers=2,
        )

        sig = ht.sign("Winternitz purely string message")
        self.assertTrue(ht.verify(sig))

    def test_tree_regeneration_logic(self):
        w = 16
        ht = ext4.HyperTree(
            keygen_fn=lambda: winternitz.generate_keys(w),
            sign_fn=lambda sk, msg: winternitz.sign(to_wots_message(msg), sk, w),
            verify_fn=lambda sig, pk, msg: winternitz.verify(to_wots_message(msg), sig, pk, w),
            hash_fn=merkle.leaf_hash,
            subtree_size=2,
            num_layers=2,
        )

        self.assertTrue(ht.verify(ht.sign("Message 1")))
        self.assertTrue(ht.verify(ht.sign("Message 2")))

        sig3 = ht.sign("Message 3")
        self.assertTrue(ht.verify(sig3))
        self.assertEqual(sig3["key_indices"][1], 1)


if __name__ == "__main__":
    unittest.main()
