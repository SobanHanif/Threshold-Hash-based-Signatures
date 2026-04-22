import unittest

from . import _path  # noqa: F401
import lamport


class TestLamport(unittest.TestCase):
    def test_round_trip(self):
        sk, pk = lamport.generate_keys()
        msg = "soban is cute"
        sig = lamport.sign(msg, sk)
        self.assertTrue(lamport.verify(msg, sig, pk))

    def test_tamper_fails(self):
        sk, pk = lamport.generate_keys()
        msg = "brigsort"
        sig = lamport.sign(msg, sk)
        self.assertFalse(lamport.verify(msg + "jeff", sig, pk))

    def test_wrong_pk_fails(self):
        sk1, _ = lamport.generate_keys()
        _, pk2 = lamport.generate_keys()
        sig = lamport.sign("msg", sk1)
        self.assertFalse(lamport.verify("msg", sig, pk2))


if __name__ == "__main__":
    unittest.main()
