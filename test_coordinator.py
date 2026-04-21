import unittest
import lamport, threshold


from coordinator import Coordinator

NParties = 4

class TestCoordinator(unittest.TestCase):
    # Test: adding an empty party should raise ValueError.
    def test_add_party_empty(self):
        coordinator = Coordinator("public_key")

        with self.assertRaises(ValueError):
            coordinator.add_party("")

    # Test: attempt to add a party which already exists in the coordinator
    def test_existing_party(self):
        coordinator = Coordinator("public_key")
        coordinator.add_party("p1")

        #trying to add existing party
        with self.assertRaises(ValueError):
            coordinator.add_party("p1")


    # Test: Valid party added successfully 
    def test_addParty_scess(self):
        crd = Coordinator("public_key")
        crd.add_party("p1")
        self.assertIn("p1", crd.parties)
    
    # Test : different distinct parties can be added
    def test_diff_parties(self):
        crd = Coordinator("public_key")
        crd.add_party("p1")
        crd.add_party("p2")
        # will be valid when length of added parties is 2
        self.assertEqual(len(crd.parties), 2) 



class TestCmbSigShares(unittest.TestCase):

    def setUp(self):
        self.sk, self.pk = lamport.generate_keys()
        self.shares = threshold.split_secret_key(self.sk, NParties) 
        self.coordinator = Coordinator(self.pk) 

        self.message = "hello"

    def test_combined_match_valid(self):
        
        # Test: combining shares to give the same signature as signing with key
        sigShares = []

        for s in self.shares:
            sig = lamport.sign(self.message, s)
            sigShares.append(sig)
        
        #both must match
        cmb = self.coordinator.comb_sig_shares(sigShares)

        self.assertEqual(cmb, lamport.sign(self.message, self.sk))

    #Test: Valid if Combined Signature has 256 length
    def test_is_valid_comb_sign_256_chars(self):

        shares = [lamport.sign(self.message, s) 
                  for s in self.shares]
        
        comb = self.coordinator.comb_sig_shares(shares)

        self.assertEqual(len(comb), 256)
        
class TestVerification(unittest.TestCase):
    # Setup: generating lamport key pair, split into SK into Nparties Share
    # creating coordinator with PK and setting a test messagje
    def setUp(self):
        self.sk, self.pk = lamport.generate_keys()
        self.shares = threshold.split_secret_key(self.sk, NParties)
        self.coordinator = Coordinator(self.pk)

        self.message = "hello123 "


    #Test: signing each of the secret share and independing and combing the signature
    #      shares via XOR producing a valid signature, that passes verification
    def test_is_valid_sig(self):
        sig_shares = []

        for s in self.shares:
            sig = lamport.sign(self.message, s)
            sig_shares.append(sig)

        cmb = self.coordinator.comb_sig_shares(sig_shares) 
        res = self.coordinator.verify_Signature(self.message, cmb)

        self.assertTrue(res) 
 
if __name__ == "__main__":
    unittest.main()
