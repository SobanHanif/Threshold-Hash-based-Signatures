import threshold
import lamport

class Coordinator:
    # The coordinator manages the threshold signing workflow.
    # It coordinates the parties but does not store the full secret key.
    def __init__(self, public_key, parties=None):
        # PK used to verify the final signature.
        self.public_key = public_key

        # Parties - participants which hold each secret key share.
        self.parties = list(parties or [])


    def add_party(self, Party):
        # raise error if Party is NONE
        if Party is None:
            raise ValueError("Party can't be None")

        # raise error if party is empty
        if Party == "":
            raise ValueError("Party can't be empty")

        # raise error if party is already added
        if Party in self.parties:
            raise ValueError("Party is already added")
        
        self.parties.append(Party)

    def collect_sign_shares(self, message):
        # Store the signature shares in an array , initially emptyu 
        signature_shares = []

        # Send the same message to every registered party
        for p in self.parties:
            sig_share = p.sign(message)

            signature_shares.append(sig_share)

        return signature_shares
    
    # Module for comboning all the shared-signaturesm to be used for final signature
    def comb_sig_shares(self, sig_shares):
        return threshold.combine_signatures(sig_shares)
    
    def sign (self, message):
            # Collect all signatures ion the sig_sahre array & combine them to a final signature
            sig_shares = self.collect_sign_shares(message)
            final_signature = self.comb_sig_shares(sig_shares)
            return final_signature
    

    # check the final combined signature is valid using our pUblic key 
    def verify_Signature(self, message, signature):
        return lamport.verify(message, signature, self.public_key)