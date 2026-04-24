import hashlib
import unittest
import ext4
import lamport
import winternitz
import merkle
# og lamport is a list so need to concat
def lamport_hash_pk(pk):
    parts = [p for pair in pk for p in pair]
    return hashlib.sha256(b"".join(parts)).digest()

class TestExt4HyperTree(unittest.TestCase):
    def setUp(self):
        """Initialize standard parameters for testing."""
        self.subtree_size = 2  # Small size to trigger exhaustion quickly
        self.layers = 2
        self.w = 16

    def test_protocol_agnosticism(self):
        #amport vs witernits
        ht_lamport = ext4.HyperTree(
            keygen_fn=lamport.generate_keys,
            sign_fn=lambda sk, msg: lamport.sign(msg, sk),
            verify_fn=lambda sig, pk, msg: lamport.verify(msg, sig, pk),
            hash_fn=lamport_hash_pk,
            subtree_size=self.subtree_size,
            num_layers=self.layers,
        )
        sig_l = ht_lamport.sign("Testing Lamport")
        self.assertTrue(ht_lamport.verify(sig_l), "Lamport verification failed")

        ht_wint = ext4.HyperTree(
            keygen_fn=lambda: winternitz.generate_keys(self.w),
            sign_fn=lambda sk, msg: winternitz.sign(msg, sk, self.w),
            verify_fn=lambda sig, pk, msg: winternitz.verify(msg, sig, pk, self.w),
            hash_fn=merkle.leaf_hash,
            subtree_size=self.subtree_size,
            num_layers=self.layers,
        )
        sig_w = ht_wint.sign("Testing Winternitz")
        self.assertTrue(ht_wint.verify(sig_w), "Winternitz verification failed")

    def test_dynamic_subtree_regeneration(self):
        ht = ext4.HyperTree(
            keygen_fn=lambda: winternitz.generate_keys(self.w),
            sign_fn=lambda sk, msg: winternitz.sign(msg, sk, self.w),
            verify_fn=lambda sig, pk, msg: winternitz.verify(msg, sig, pk, self.w),
            hash_fn=merkle.leaf_hash,
            subtree_size=2, #  sign 2 itemseach
            num_layers=2,
        )

        ht.sign("Msg 1")
        ht.sign("Msg 2")

        # should trigger a new subtree, as 1 subtree has signed 2
        sig3 = ht.sign("Msg 3")
        
        self.assertTrue(ht.verify(sig3))

        self.assertEqual(sig3["key_indices"][0], 0, "should have a new subtree here/new layer @ 0")
        self.assertEqual(sig3["key_indices"][1], 1, "top tree is 2nd leaf")

    def test_signature_structure(self):
        num_layers = 3
        ht = ext4.HyperTree(
            keygen_fn=lambda: winternitz.generate_keys(self.w),
            sign_fn=lambda sk, msg: winternitz.sign(msg, sk, self.w),
            verify_fn=lambda sig, pk, msg: winternitz.verify(msg, sig, pk, self.w),
            hash_fn=merkle.leaf_hash,
            subtree_size=2,
            num_layers=num_layers,
        )

        sig = ht.sign("Deep Tree Test")
        
        # Verify lists length matches num_layers
        self.assertEqual(len(sig["sigs"]), num_layers)
        self.assertEqual(len(sig["pks"]), num_layers)
        self.assertEqual(len(sig["auth_paths"]), num_layers)

    def test_tamper_resistance(self):
        ht = ext4.HyperTree(
            keygen_fn=lamport.generate_keys,
            sign_fn=lambda sk, msg: lamport.sign(msg, sk),
            verify_fn=lambda sig, pk, msg: lamport.verify(msg, sig, pk),
            hash_fn=lamport_hash_pk,
            subtree_size=2,
            num_layers=2,
        )
        
        sig = ht.sign("Authentic Message")

        sig_bad_msg = sig.copy()
        sig_bad_msg["message"] = b"Tampered Message"
        self.assertFalse(ht.verify(sig_bad_msg))

        sig_bad_idx = sig.copy()
        sig_bad_idx["key_indices"] = [0, 99]
        self.assertFalse(ht.verify(sig_bad_idx))

if __name__ == "__main__":
    unittest.main()