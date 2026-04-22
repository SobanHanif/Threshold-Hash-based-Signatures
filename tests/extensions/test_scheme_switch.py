import unittest

from tests import _path
from kofn import kofn_keygen, kofn_sign, kofn_verify
from ots import LamportOTS, WinternitzOTS


def _run_protocol(ots, n, k, selected, message):
    state = kofn_keygen(n, k, ots)
    sig = kofn_sign(selected, message, state)
    return kofn_verify(message, sig, state["root"], n, k, ots)


class TestSchemeSwitch(unittest.TestCase):
    def test_same_harness_runs_both_schemes(self):
        n, k, selected, message = 5, 3, [0, 2, 4], "shared harness input"
        for ots in (LamportOTS(), WinternitzOTS(w=16)):
            with self.subTest(scheme=ots.name):
                self.assertTrue(_run_protocol(ots, n, k, selected, message))

    def test_scheme_switch_no_protocol_code_change(self):
        params = dict(n=4, k=2, selected=[1, 3], message="identical input")
        self.assertTrue(_run_protocol(ots=LamportOTS(), **params))
        self.assertTrue(_run_protocol(ots=WinternitzOTS(w=16), **params))
        self.assertTrue(_run_protocol(ots=WinternitzOTS(w=256), **params))


if __name__ == "__main__":
    unittest.main()
