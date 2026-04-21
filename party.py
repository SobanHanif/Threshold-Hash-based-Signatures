from lamport import sign

class Party:

    def __init__ (self, share):
        self.share = share

    def sign(self, message):
        return sign(message, self.share)