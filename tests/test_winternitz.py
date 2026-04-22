import unittest

from . import _path  # noqa: F401
import winternitz


class TestWinternitz(unittest.TestCase):
    def test_round_trip_multiple_w(self):
        for w in (4, 16, 256):
            with self.subTest(w=w):
                sk, pk = winternitz.generate_keys(w)
                msg = f"hello wots w={w}"
                sig = winternitz.sign(msg, sk, w)
                self.assertTrue(winternitz.verify(msg, sig, pk, w))

    def test_tamper_fails(self):
        w = 16
        sk, pk = winternitz.generate_keys(w)
        sig = winternitz.sign("abc", sk, w)
        self.assertFalse(winternitz.verify("abd", sig, pk, w))

    def test_wrong_pk_fails(self):
        w = 16
        sk1, _ = winternitz.generate_keys(w)
        _, pk2 = winternitz.generate_keys(w)
        sig = winternitz.sign("msg", sk1, w)
        self.assertFalse(winternitz.verify("msg", sig, pk2, w))


if __name__ == "__main__":
    unittest.main()
