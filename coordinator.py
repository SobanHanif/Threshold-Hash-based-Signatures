class Coordinator:
    # The coordinator manages the threshold signing workflow.
    # It coordinates the parties but does not store the full secret key.
    def __init__(self, public_key, parties=None):
        # PK used to verify the final signature.
        self.public_key = public_key

        # Parties - participants which hold each secret key share.
        self.parties = list(parties or [])


    def add_party (self, Party):
        
        # raise error if party is already added

        if Party is self.parties:
            raise ValueError("Party is already added")
        
        # raise error if Party is NONE
        if Party is None:
            raise ValueError("Party can't be None")
        
        

        self.parties.append(Party)


