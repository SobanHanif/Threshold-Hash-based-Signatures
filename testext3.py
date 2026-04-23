import hashlib
import unittest

import merkle
from ext3 import BatchHandler

N_PKS = 5
# Global mock public keys list to mimic original script's behavior
PKS = [hashlib.sha256(f"pk_{i}".encode()).digest() for i in range(N_PKS)]


# --- Mock Functions for Testing ---

def mock_signature_fn(message_hash, key_id):
    """Simulates the threshold XOR signature."""
    # ts combined XOR shares from n parties
    return hashlib.sha256(message_hash + str(key_id).encode()).digest()

def mock_verify_fn(message_hash, sig, pk):
    """Simulates the verification of a Lamport/WOTS signature."""
    # mocks Lamport verify function
    expected = hashlib.sha256(message_hash + str(PKS.index(pk)).encode()).digest()
    return sig == expected


# Helper to initialize the BatchHandler
def setup_handler(batch_size=2, pks=None):
    if pks is None:
        pks = PKS[:4]  # Default to 4 keys like the original script
    handler = BatchHandler(batch_size=batch_size, pks=pks, signature_fn=mock_signature_fn)
    return handler


class TestBatchHandler(unittest.TestCase):
    
    # Test adding messages and verifying a proof against the outer root
    def test_successful_batch_verification(self):
        handler = setup_handler(batch_size=2)
        messages = [b"apple", b"banana", b"cherry"]
        
        for msg in messages:
            handler.addMessage(msg)

        self.assertGreater(len(handler.completed_batches), 0, "At least one batch should be completed")
        self.assertEqual(
            [m.decode() for m in handler.completed_batches[0]['messages']], 
            ["apple", "banana"], 
            "Batch 0 should contain exactly 'apple' and 'banana'"
        )

        proof = handler.get_proof(batch_index=0, message_index=1)
        self.assertEqual(proof['message'], b"banana", "Proof should be generated for 'banana'")
        
        is_valid = handler.batch_verify(proof, handler.outer_root, mock_verify_fn)
        self.assertTrue(is_valid, "Message should verify successfully against Outer Root")

    # Test that a tampered message fails verification
    def test_tampered_message_fails(self):
        handler = setup_handler(batch_size=2)
        handler.addMessage(b"apple")
        handler.addMessage(b"banana")

        proof = handler.get_proof(batch_index=0, message_index=1)
        proof_bad = proof.copy()
        proof_bad["message"] = b"evil_apple"
        
        is_valid_bad = handler.batch_verify(proof_bad, handler.outer_root, mock_verify_fn)
        self.assertFalse(is_valid_bad, "Verifier should reject the fake/tampered message")

    # Test that getting a proof from an incomplete batch fails
    def test_single_message_no_batch(self):
        handler = setup_handler(batch_size=2)
        handler.addMessage(b"only")

        self.assertEqual(len(handler.completed_batches), 0, "Batch should not be created yet")

        with self.assertRaises(Exception, msg="Should block proof generation from an incomplete batch"):
            handler.get_proof(0, 0)

    # Test an exact batch size verification
    def test_exact_batch(self):
        handler = setup_handler(batch_size=2)
        handler.addMessage(b"a")
        handler.addMessage(b"b")

        self.assertEqual(len(handler.completed_batches), 1, "Exactly one batch should be completed")

        proof = handler.get_proof(0, 0)
        self.assertTrue(handler.batch_verify(proof, handler.outer_root, mock_verify_fn), "Exact batch should verify successfully")

    # Test that multiple batches process and verify correctly
    def test_multiple_batches(self):
        handler = setup_handler(batch_size=2)
        msgs = [b"a", b"b", b"c", b"d"]
        for m in msgs:
            handler.addMessage(m)

        self.assertEqual(len(handler.completed_batches), 2, "Exactly two batches should be completed")

        # Test message from the second batch
        proof = handler.get_proof(1, 0)  # "c"
        self.assertTrue(handler.batch_verify(proof, handler.outer_root, mock_verify_fn), "Message from the second batch should verify")

    # Test verification of the last index in a standard batch
    def test_last_index_in_batch(self):
        handler = setup_handler(batch_size=2)
        handler.addMessage(b"x")
        handler.addMessage(b"y")

        proof = handler.get_proof(0, 1)  # last element
        self.assertTrue(handler.batch_verify(proof, handler.outer_root, mock_verify_fn), "Last index in batch should verify")

    # Test that requesting a non-existent batch throws an error
    def test_invalid_batch_index(self):
        handler = setup_handler(batch_size=2)
        handler.addMessage(b"a")
        handler.addMessage(b"b")

        with self.assertRaises(Exception, msg="Invalid batch index should be rejected"):
            handler.get_proof(5, 0)

    # Test that requesting a non-existent message index throws an error
    def test_invalid_message_index(self):
        handler = setup_handler(batch_size=2)
        handler.addMessage(b"a")
        handler.addMessage(b"b")

        with self.assertRaises(Exception, msg="Invalid message index should be rejected"):
            handler.get_proof(0, 5)

    # Test that altering the inner Merkle path causes verification to fail
    def test_tampered_merkle_proof(self):
        handler = setup_handler(batch_size=2)
        handler.addMessage(b"a")
        handler.addMessage(b"b")

        proof = handler.get_proof(0, 0)
        
        # Tamper with Merkle path
        proof["inner_path"][0] = b"fake_hash"

        self.assertFalse(handler.batch_verify(proof, handler.outer_root, mock_verify_fn), "Tampered Merkle proof should be rejected")

    # Test that the outer root remains deterministic across different instances
    def test_outer_root_stability(self):
        handler1 = setup_handler(batch_size=2)
        handler2 = setup_handler(batch_size=2)

        self.assertEqual(handler1.outer_root, handler2.outer_root, "Outer root should be completely deterministic")

    # Test verifying messages correctly across larger batches
    def test_large_full_batches(self):
        batch_sz = 10
        handler = setup_handler(batch_size=batch_sz, pks=PKS)
        
        total_messages = 20
        for i in range(total_messages):
            handler.addMessage(f"msg_{i}".encode())
        
        self.assertEqual(len(handler.completed_batches), 2, f"Expected 2 batches, got {len(handler.completed_batches)}")

        # Verify a message from Batch 0
        proof_batch_0 = handler.get_proof(batch_index=0, message_index=9)
        self.assertEqual(proof_batch_0["message"], b"msg_9", "Should fetch msg_9")
        self.assertTrue(handler.batch_verify(proof_batch_0, handler.outer_root, mock_verify_fn), "Message from large batch 0 should verify")
        
        # Verify a message from Batch 1
        proof_batch_1 = handler.get_proof(batch_index=1, message_index=0)
        self.assertEqual(proof_batch_1["message"], b"msg_10", "Should fetch msg_10")
        self.assertTrue(handler.batch_verify(proof_batch_1, handler.outer_root, mock_verify_fn), "Message from large batch 1 should verify")


if __name__ == "__main__":
    unittest.main()