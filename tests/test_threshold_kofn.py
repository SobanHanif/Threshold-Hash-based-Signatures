import unittest

from . import _path
from ots import LamportOTS, WinternitzOTS
from threshold import kofn_keygen, kofn_sign, kofn_verify


SCHEMES = [
    ("lamport", lambda: LamportOTS()),
    ("wots-w4", lambda: WinternitzOTS(w=4)),
    ("wots-w16", lambda: WinternitzOTS(w=16)),
    ("wots-w256", lambda: WinternitzOTS(w=256)),
]


class TestThresholdKofN(unittest.TestCase):
    def test_round_trip_each_scheme(self):
        for name, factory in SCHEMES:
            with self.subTest(scheme=name):
                ots = factory()
                state = kofn_keygen(5, 3, ots)
                sig = kofn_sign([0, 2, 4], "msg", state)
                self.assertTrue(kofn_verify("msg", sig, state["root"], 5, 3, ots))

    def test_tamper_fails_each_scheme(self):
        for name, factory in SCHEMES:
            with self.subTest(scheme=name):
                ots = factory()
                state = kofn_keygen(5, 3, ots)
                sig = kofn_sign([0, 2, 4], "msg", state)
                self.assertFalse(kofn_verify("msg!", sig, state["root"], 5, 3, ots))

    def test_different_subsets_each_scheme(self):
        for name, factory in SCHEMES:
            with self.subTest(scheme=name):
                ots = factory()
                state = kofn_keygen(5, 3, ots)
                s1 = kofn_sign([0, 1, 2], "m", state)
                s2 = kofn_sign([2, 3, 4], "m", state)
                self.assertNotEqual(s1["subset_idx"], s2["subset_idx"])
                self.assertTrue(kofn_verify("m", s1, state["root"], 5, 3, ots))
                self.assertTrue(kofn_verify("m", s2, state["root"], 5, 3, ots))

    def test_wrong_subset_size_rejected(self):
        ots = WinternitzOTS(w=16)
        state = kofn_keygen(5, 3, ots)
        with self.assertRaises(ValueError):
            kofn_sign([0, 1], "msg", state)
        with self.assertRaises(ValueError):
            kofn_sign([0, 1, 2, 3], "msg", state)

    def test_out_of_range_party_rejected(self):
        ots = WinternitzOTS(w=16)
        state = kofn_keygen(5, 3, ots)
        with self.assertRaises(ValueError):
            kofn_sign([0, 1, 99], "msg", state)

    def test_reuse_guard(self):
        ots = WinternitzOTS(w=16)
        state = kofn_keygen(5, 3, ots)
        kofn_sign([0, 1, 2], "first", state)
        with self.assertRaises(RuntimeError):
            # same subset a second time must be rejected
            kofn_sign([0, 1, 2], "second", state)

    def test_verifier_rejects_bad_subset_idx(self):
        ots = WinternitzOTS(w=16)
        state = kofn_keygen(5, 3, ots)
        sig = kofn_sign([0, 1, 2], "m", state)
        sig["subset_idx"] = 9999
        self.assertFalse(kofn_verify("m", sig, state["root"], 5, 3, ots))

    def test_verifier_rejects_wrong_auth_path(self):
        ots = WinternitzOTS(w=16)
        state = kofn_keygen(5, 3, ots)
        sig = kofn_sign([0, 1, 2], "m", state)
        # flips a bit in the auth path
        bad = bytearray(sig["auth_path"][0])
        bad[0] ^= 1
        sig["auth_path"][0] = bytes(bad)
        self.assertFalse(kofn_verify("m", sig, state["root"], 5, 3, ots))


if __name__ == "__main__":
    unittest.main()
