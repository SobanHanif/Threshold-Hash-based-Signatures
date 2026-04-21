from lamport import sign
import secrets
class Party:

    def __init__ (self, share):
        """Initialises the party class. Each party holds their randomised uint32 share."""
        self._share = secrets.token_bytes(32)


    def sign(self, message):
        return sign(message, self._share)