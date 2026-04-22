import lamport
from party import Party
from threshold import xor_bytes

# In literature, this is the 'aggregator'
class Coordinator:
    # The coordinator manages the threshold signing workflow.
    # It coordinates the parties but does not store the full secret key.
    
    def __init__(self, public_key, parties=None):
        """
        Constructor for coordinator
        Stores the public key and the parties involved in signing
        """
        if public_key is None:
            raise ValueError("public_key cannot be None")

        # PK used to verify the final signature.
        self.public_key = public_key

        # Parties - participants which hold each secret key share.
        self.parties = []

        if parties is not None:
            for p in parties:
                self.add_party(p)


    def add_party(self, p):
        # raise error if Party is NONE
        if p is None:
            raise ValueError("Party can't be None")
        if not isinstance(p, Party):
            raise TypeError("Expected a Party instance")

        # raise error if party is already added
        if any(existing.party_id == p.party_id for existing in self.parties):
            raise ValueError("Party is already added")
        
        self.parties.append(p)

    def request_signature_shares(self, message):
        """
        Ask all available parties for their signature shares.
        """
        sig_shares = []

        for p in self.parties:
            accepted, sig_share = p.receive_sign_request(message)
            if not accepted:
                raise ValueError(f"Party {p.party_id} is unavailable")
            sig_shares.append(sig_share)

        return sig_shares

    def comb_sig_shares(self, sig_shares):
        """
        Combine signature shares elementwise via XOR.
        """
        if not sig_shares:
            raise ValueError("sig_shares cannot be empty")

        sig_len = len(sig_shares[0])
        if sig_len == 0:
            raise ValueError("signature shares cannot be empty")

        for share in sig_shares:
            if len(share) != sig_len:
                raise ValueError("All signature shares must have the same length")

        combined_signature = []
        for i in range(sig_len):
            combined_value = sig_shares[0][i]
            for j in range(1, len(sig_shares)):
                combined_value = xor_bytes(combined_value, sig_shares[j][i])
            combined_signature.append(combined_value)

        return combined_signature

    def sign(self, message):
        sig_shares = self.request_signature_shares(message)
        return self.comb_sig_shares(sig_shares)

    def verify_signature(self, message, signature):
        return lamport.verify(message, signature, self.public_key)
