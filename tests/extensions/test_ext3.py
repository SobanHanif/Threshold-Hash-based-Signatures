import hashlib
import unittest

from tests import _path
from ext3 import BatchHandler


N_PKS = 5
PKS = [hashlib.sha256(f"pk_{i}".encode()).digest() for i in range(N_PKS)]


def mock_signature_fn(message_hash, key_id):
    return hashlib.sha256(message_hash + str(key_id).encode()).digest()


def mock_verify_fn(message_hash, sig, pk):
    expected = hashlib.sha256(message_hash + str(PKS.index(pk)).encode()).digest()
    return sig == expected


def setup_handler(batch_size=2, pks=None):
    if pks is None:
        pks = PKS[:4]
    return BatchHandler(batch_size=batch_size, pks=pks, signature_fn=mock_signature_fn)


class TestBatchHandler(unittest.TestCase):
    def test_successful_batch_verification(self):
        # lowkey not sure if we should use the byte type or not
        handler = setup_handler(batch_size=2)
        messages = [b"apple", b"banana", b"cherry"]

        for msg in messages:
            handler.addMessage(msg)

        self.assertGreater(len(handler.completed_batches), 0)
        self.assertEqual(
            [m.decode() for m in handler.completed_batches[0][b"messages"]],
            [b"apple", b"banana"],
        )

        proof = handler.get_proof(batch_index=0, message_index=1)
        self.assertEqual(proof["message"], "banana")
        self.assertTrue(handler.batch_verify(proof, handler.outer_root, mock_verify_fn))

    def test_tampered_message_fails(self):
        handler = setup_handler(batch_size=2)
        handler.addMessage("apple")
        handler.addMessage("banana")

        proof = handler.get_proof(batch_index=0, message_index=1)
        proof_bad = proof.copy()
        proof_bad["message"] = "evil_apple"
        self.assertFalse(handler.batch_verify(proof_bad, handler.outer_root, mock_verify_fn))

    def test_single_message_no_batch(self):
        handler = setup_handler(batch_size=2)
        handler.addMessage("only")

        self.assertEqual(len(handler.completed_batches), 0)
        with self.assertRaises(Exception):
            handler.get_proof(0, 0)

    def test_exact_batch(self):
        handler = setup_handler(batch_size=2)
        handler.addMessage("a")
        handler.addMessage("b")

        self.assertEqual(len(handler.completed_batches), 1)
        proof = handler.get_proof(0, 0)
        self.assertTrue(handler.batch_verify(proof, handler.outer_root, mock_verify_fn))

    def test_multiple_batches(self):
        handler = setup_handler(batch_size=2)
        for msg in ["a", "b", "c", "d"]:
            handler.addMessage(msg)

        self.assertEqual(len(handler.completed_batches), 2)
        proof = handler.get_proof(1, 0)
        self.assertTrue(handler.batch_verify(proof, handler.outer_root, mock_verify_fn))

    def test_last_index_in_batch(self):
        handler = setup_handler(batch_size=2)
        handler.addMessage("x")
        handler.addMessage("y")

        proof = handler.get_proof(0, 1)
        self.assertTrue(handler.batch_verify(proof, handler.outer_root, mock_verify_fn))

    def test_invalid_batch_index(self):
        handler = setup_handler(batch_size=2)
        handler.addMessage("a")
        handler.addMessage("b")

        with self.assertRaises(Exception):
            handler.get_proof(5, 0)

    def test_invalid_message_index(self):
        handler = setup_handler(batch_size=2)
        handler.addMessage("a")
        handler.addMessage("b")

        with self.assertRaises(Exception):
            handler.get_proof(0, 5)

    def test_tampered_merkle_proof(self):
        handler = setup_handler(batch_size=2)
        handler.addMessage("a")
        handler.addMessage("b")

        proof = handler.get_proof(0, 0)
        proof["inner_path"][0] = "fake_hash"
        self.assertFalse(handler.batch_verify(proof, handler.outer_root, mock_verify_fn))

    def test_outer_root_stability(self):
        handler1 = setup_handler(batch_size=2)
        handler2 = setup_handler(batch_size=2)
        self.assertEqual(handler1.outer_root, handler2.outer_root)

    def test_large_full_batches(self):
        handler = setup_handler(batch_size=10, pks=PKS)

        for i in range(20):
            handler.addMessage(f"msg_{i}".encode())

        self.assertEqual(len(handler.completed_batches), 2)

        proof_batch_0 = handler.get_proof(batch_index=0, message_index=9)
        self.assertEqual(proof_batch_0["message"], "msg_9")
        self.assertTrue(
            handler.batch_verify(proof_batch_0, handler.outer_root, mock_verify_fn)
        )

        proof_batch_1 = handler.get_proof(batch_index=1, message_index=0)
        self.assertEqual(proof_batch_1["message"], "msg_10")
        self.assertTrue(
            handler.batch_verify(proof_batch_1, handler.outer_root, mock_verify_fn)
        )


if __name__ == "__main__":
    unittest.main()
