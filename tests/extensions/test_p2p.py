import unittest

from tests import _path
import lamport
import threshold

from party import Party
from p2p import P2PNetwork

N_PARTIES = 100


# Helper to generate keys, split into shares and build P2P network
def setup_network():
    sk, pk = lamport.generate_keys()
    shares = threshold.split_secret_key(sk, N_PARTIES)

    parties = [Party(party_id=i, sk_share=shares[i]) for i in range(N_PARTIES)]
    network = P2PNetwork(parties, pk)
    return sk, pk, parties, network


class TestP2PNetwork(unittest.TestCase):
    # Test signing success
    def test_successful_p2p_signing(self):
        _, pk, _, network = setup_network()
        message = "hello p2p"
        sig, ok = network.initiate_signing(0, message)

        self.assertTrue(ok, "Signing should succeed")
        self.assertEqual(len(sig), 256, "Signature should be 256 elements long")
        self.assertTrue(lamport.verify(message, sig, pk), "Signature should verify")

    # Test n-of-n signing fails if a party is unavailable
    def test_unavailable_party_fails(self):
        _, _, parties, network = setup_network()
        parties[2].set_availability(False)

        sig, ok = network.initiate_signing(0, "hello p2p")
        self.assertFalse(ok, "Signing should fail if a party is unavailable")
        self.assertIsNone(sig, "No signature should be returned")

    # Test combined signature fails verification if the message is changed
    def test_tampered_message_fails(self):
        _, pk, _, network = setup_network()
        message = "hello p2p"
        sig, _ = network.initiate_signing(0, message)

        self.assertFalse(
            lamport.verify("tampered", sig, pk),
            "Tampered message should fail verification",
        )

    # Test any party in the network initiates the signing
    def test_different_initiator(self):
        _, pk, _, network = setup_network()
        message = "hello p2p"

        # Party 2 initiates instead of Party 0
        sig, ok = network.initiate_signing(2, message)
        self.assertTrue(ok, "Party 2 should be able to initiate")
        self.assertTrue(lamport.verify(message, sig, pk))


if __name__ == "__main__":
    unittest.main()
