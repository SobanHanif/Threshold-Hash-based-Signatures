class Coordinator:
    # The coordinator manages the threshold signing workflow.
    #It coordinates the parties but does not store the full secret key. 
    def __init__(self, public_key, parties=None):
        # PK used to verify the final signature. 
        self.public_key = public_key

        # Parties - participants which hold each secret key pair. 
        self.parties = list(parties or [])
