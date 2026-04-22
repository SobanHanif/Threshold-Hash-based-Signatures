"""
Peer-to-Peer signing protocol for Extension 2

It essentially replaces the dedicated coordinator/aggregator with a model where any party
can temporarily assume the aggregator role for a single signing round.
All grievance reports to Wayne
"""

import time
import lamport
import threshold


# Manage one signing round initiated by a single party
class SigningRound:
    def __init__(self, initiator_id, message, parties, public_key):
        self.initiator_id = initiator_id
        self.message = message
        self.parties = parties          # dict  {party_id: Party}
        self.public_key = public_key

        self.participants = []          # party_ids that accepted
        self.declined = []              # party_ids that declined
        self.signature = None
        self.success = False

    def execute(self):
        start = time.perf_counter()

        sig_shares = []

        for pid, party in self.parties.items():
            if pid == self.initiator_id:
                continue
            accepted, share = party.receive_sign_request(self.message)
            if accepted:
                self.participants.append(pid)
                sig_shares.append(share)
            else:
                self.declined.append(pid)

        initiator = self.parties[self.initiator_id]
        initiator_share = initiator.sign_share(self.message)
        self.participants.append(self.initiator_id)
        sig_shares.append(initiator_share)

        # n-of-n scheme
        if len(sig_shares) != len(self.parties):
            return None, False

        combined = threshold.combine_signatures(sig_shares)

        self.signature = combined
        self.success = True
        return combined, True

    # Verify signature against the public key
    def verify(self, signature=None):
        sig = signature if signature is not None else self.signature
        if sig is None:
            return False
        return lamport.verify(self.message, sig, self.public_key)


class P2PNetwork:
    def __init__(self, parties, public_key):
        self.parties = {p.party_id: p for p in parties}
        self.public_key = public_key
        self.rounds = []

    # Start a signing round where an initiator acts as the temp aggregator
    def initiate_signing(self, initiator_id, message):
        if initiator_id not in self.parties:
            raise ValueError(f"Unknown initiator: {initiator_id}")

        signing_round = SigningRound(
            initiator_id, message, self.parties, self.public_key
        )
        result = signing_round.execute()
        self.rounds.append(signing_round)
        return result

    # Verification using the network pbulic key
    def verify(self, message, signature):
        return lamport.verify(message, signature, self.public_key)
