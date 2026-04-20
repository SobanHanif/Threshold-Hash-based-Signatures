import unittest

from coordinator import Coordinator


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
if __name__ == "__main__":
    unittest.main()
