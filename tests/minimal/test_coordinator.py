import unittest

from tests import _path
import lamport
import threshold

from coordinator import Coordinator
from party import Party

NParties = 4


class TestCoordinator(unittest.TestCase):
    # Test: adding None should raise ValueError
    def test_add_party_none(self):
        coordinator = Coordinator("public_key")

        with self.assertRaises(ValueError):
            coordinator.add_party(None)

    # Test: adding a non-Party object should raise TypeError
    def test_add_party_wrong_type(self):
        coordinator = Coordinator("public_key")

        with self.assertRaises(TypeError):
            coordinator.add_party("p1")

    # Test: attempt to add a party which already exists in the coordinator
    def test_existing_party(self):
        coordinator = Coordinator("public_key")
        p1 = Party(party_id=1)
        coordinator.add_party(p1)

        with self.assertRaises(ValueError):
            coordinator.add_party(Party(party_id=1))

    # Test: valid party added successfully
    def test_addParty_scess(self):
        crd = Coordinator("public_key")
        p1 = Party(party_id=1)
        crd.add_party(p1)
        self.assertIn(p1, crd.parties)

    # Test: different distinct parties can be added
    def test_diff_parties(self):
        crd = Coordinator("public_key")
        crd.add_party(Party(party_id=1))
        crd.add_party(Party(party_id=2))

        # will be valid when length of added parties is 2
        self.assertEqual(len(crd.parties), 2)


class TestSignatureRequests(unittest.TestCase):
    def setUp(self):
        self.sk, self.pk = lamport.generate_keys()
        self.shares = threshold.split_secret_key(self.sk, NParties)
        self.parties = [Party(party_id=i, sk_share=self.shares[i]) for i in range(NParties)]
        self.coordinator = Coordinator(self.pk, self.parties)
        self.message = "hello"

    # Test: coordinator gets one signature share from each party
    def test_request_sig_shares_count(self):
        sig_shares = self.coordinator.request_signature_shares(self.message)

        self.assertEqual(len(sig_shares), NParties)
        self.assertEqual(len(sig_shares[0]), 256)

    # Test: unavailable party should stop the signing request
    def test_unavailable_party_raises(self):
        self.parties[2].set_availability(False)

        with self.assertRaises(ValueError):
            self.coordinator.request_signature_shares(self.message)


class TestThresholdHelpers(unittest.TestCase):
    def test_reconstruct_secret_key(self):
        sk, _ = lamport.generate_keys()
        shares = threshold.split_secret_key(sk, NParties)
        reconstructed = threshold.reconstruct_secret_key(shares)

        self.assertEqual(reconstructed, sk)


class TestCmbSigShares(unittest.TestCase):
    def setUp(self):
        self.sk, self.pk = lamport.generate_keys()
        self.shares = threshold.split_secret_key(self.sk, NParties)
        self.coordinator = Coordinator(self.pk)

        self.message = "hello"

    # Test: combining shares should give the same signature as signing with key
    def test_combined_match_valid(self):
        sigShares = []

        for s in self.shares:
            sig = lamport.sign(self.message, s)
            sigShares.append(sig)

        cmb = self.coordinator.comb_sig_shares(sigShares)

        self.assertEqual(cmb, lamport.sign(self.message, self.sk))

    # Test: valid if combined signature has 256 length
    def test_is_valid_comb_sign_256_chars(self):
        shares = [lamport.sign(self.message, s)
                  for s in self.shares]

        comb = self.coordinator.comb_sig_shares(shares)

        self.assertEqual(len(comb), 256)


class TestSigningFlow(unittest.TestCase):
    # Setup: generate Lamport key pair, split secret key into NParties shares
    def setUp(self):
        self.sk, self.pk = lamport.generate_keys()
        self.shares = threshold.split_secret_key(self.sk, NParties)
        self.parties = [Party(party_id=i, sk_share=self.shares[i]) for i in range(NParties)]
        self.coordinator = Coordinator(self.pk, self.parties)

        self.message = "hello123 "

    # Test: collecting signature shares and combining them gives a valid signature
    def test_is_valid_sig(self):
        cmb = self.coordinator.sign(self.message)
        res = lamport.verify(self.message, cmb, self.pk)

        self.assertTrue(res)

    # Test: bytes messages should work the same as string messages
    def test_is_valid_sig_bytes_message(self):
        message = b"hello123 "
        cmb = self.coordinator.sign(message)
        res = self.coordinator.verify_signature(message, cmb)

        self.assertTrue(res)


if __name__ == "__main__":
    unittest.main()
