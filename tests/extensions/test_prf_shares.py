import unittest

from tests import _path
import lamport
from prf_shares import (
    derive_share,
    merkle_keygen_prf,
    reconstruct_leaf_secret,
)


class TestPrfShares(unittest.TestCase):
    def test_reconstruction_matches_original_secret_key(self):
        state = merkle_keygen_prf(4, 2)
        reconstructed = reconstruct_leaf_secret(state, 0)
        self.assertEqual(reconstructed, state["leaf_secret_keys"][0])

    def test_merkle_round_trip(self):
        state = merkle_keygen_prf(4, 3)
        sig = lamport.merkle_sign("hello prf merkle", 1, state)
        self.assertTrue(lamport.merkle_verify("hello prf merkle", sig, state["root"]))

    def test_tampered_message_fails(self):
        state = merkle_keygen_prf(4, 3)
        sig = lamport.merkle_sign("hello prf merkle", 0, state)
        self.assertFalse(lamport.merkle_verify("tampered", sig, state["root"]))

    def test_leaf_reuse_guard(self):
        state = merkle_keygen_prf(4, 3)
        lamport.merkle_sign("first", 0, state)
        with self.assertRaises(RuntimeError):
            lamport.merkle_sign("second", 0, state)

    def test_derive_party_share_is_deterministic(self):
        prf_key = b"\x11" * 32
        share_1 = derive_share(prf_key, 2, 5, 17, 1)
        share_2 = derive_share(prf_key, 2, 5, 17, 1)
        share_3 = derive_share(prf_key, 2, 5, 17, 0)
        self.assertEqual(share_1, share_2)
        self.assertNotEqual(share_1, share_3)


if __name__ == "__main__":
    unittest.main()
