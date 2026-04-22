import unittest

from tests import _path
from lamport import merkle_keygen, merkle_sign, merkle_verify


class TestMerkleLamport(unittest.TestCase):
    def test_round_trip(self):
        state = merkle_keygen(4, 3)
        sig = merkle_sign("hello merkle", 0, state)

        self.assertTrue(merkle_verify("hello merkle", sig, state["root"]))

    def test_tampered_message_fails(self):
        state = merkle_keygen(4, 3)
        sig = merkle_sign("hello merkle", 1, state)

        self.assertFalse(merkle_verify("tampered", sig, state["root"]))

    def test_reuse_guard(self):
        state = merkle_keygen(4, 3)
        merkle_sign("first", 0, state)

        with self.assertRaises(RuntimeError):
            merkle_sign("second", 0, state)


if __name__ == "__main__":
    unittest.main()
