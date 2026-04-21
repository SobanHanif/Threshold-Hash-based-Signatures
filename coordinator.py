import threshold
import lamport
import party

import copy

# In literature, this is the 'aggregator'
class Coordinator:
    # The coordinator manages the threshold signing workflow.
    # It coordinates the parties but does not store the full secret key.
    
    def __init__(self, public_key, parties=None, secret_array=None):
        """
        Constructor for coordinator
        Stores the other parties, and uses the secret array to generate its own shares
        If the share generation is to be moved outside of coordinator (i.e. accessor concerns),
        all logic is in construct_coordinator_share
        """
        # PK used to verify the final signature.
        self.public_key = public_key

        # Parties - participants which hold each secret key share.
        self.parties = list(parties or [])

        # Share
        self.share = self.construct_coordinator_share(secret_array)


    def add_party(self, p):
        # raise error if Party is NONE
        if p is None:
            raise ValueError("Party can't be None")

        # raise error if party is empty
        if p == "":
            raise ValueError("Party can't be empty")

        # raise error if party is already added
        if p in self.parties:
            raise ValueError("Party is already added")
        
        self.parties.append(p)
    # coordinator is the final nth party, but as of now it requires you to construct the share
    def construct_coordinator_share(self, secret_array):
        # A sign share is simply, for a normal party, the randomised message they store
        # secrets is a 256 length array of pairs
        temp_arr = copy.deepcopy(secret_array)
        
        prefix_xor = 0
        for p in self.parties:
            prefix_xor ^= p.share

        # The coordinator share: r_n= secret ^ r1 ^ r2 ^ ... ^ r_n - 1 
        signature_shares = [[pair[0] ^ prefix_xor, pair[1] ^ prefix_xor] for pair in temp_arr]

        return signature_shares