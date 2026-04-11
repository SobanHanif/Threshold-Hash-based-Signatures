import unittest

from coordinator import Coordinator


class TestCoordinator(unittest.TestCase):

    # Test: Adding empty Party to Coordinator : 
    # expecTed result - valuerror
    def test_add_party_empty(self):
        coordinator = Coordinator("public_key")

        with self.assertRaises(ValueError):
            coordinator.add_party("")


if __name__ == "__main__":
    unittest.main()
