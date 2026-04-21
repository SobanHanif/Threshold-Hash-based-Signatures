import secrets
class Party:
    def __init__ (self):
        """Initialises the party class. Each party holds their randomised uint32 share."""
        self.share = secrets.token_bytes(32)