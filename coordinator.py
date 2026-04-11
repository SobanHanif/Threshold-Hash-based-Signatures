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
        # To Store signature share returned by each of the parties
        signature_shares = []

        # Send the same message to every registered party.
        for p in self.parties:
            # Each party signs using its own secret-key share.
            sig_share = p.sign(message)

            # Add that party's signature share to the list.
            signature_shares.append(sig_share)

        # Return all collected signature shares to the coordinator.
        return signature_shares
