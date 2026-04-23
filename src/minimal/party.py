import lamport


class Party:
    def __init__(self, party_id=None, sk_share=None):
        self.party_id = party_id
        self.sk_share = sk_share
        self.available = True
        # Kept for compatibility with coordinator.py
        # self.share = secrets.token_bytes(32)

    def sign_share(self, message):
        if self.sk_share is None:
            raise ValueError("Party has no secret-key share assigned")
        return lamport.sign(message, self.sk_share)

    def receive_sign_request(self, message):
        if not self.available:
            return False, None
        return True, self.sign_share(message)

    def set_availability(self, available):
        self.available = available