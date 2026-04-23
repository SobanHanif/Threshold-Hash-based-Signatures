import unittest
import hashlib

import ext4
import lamport
import winternitz
import merkle

def lamport_hash_pk(pk):
   
  parts = [p for pair in pk for p in pair]
  return hashlib.sha256(b"".join(parts)).digest()

class TestExt4HyperTree(unittest.TestCase):

  def test_hypertree_lamport(self):
    ht = ext4.HyperTree(
      keygen_fn=lamport.generate_keys,
      
      sign_fn=lambda sk, msg: lamport.sign(msg, sk),
      verify_fn=lambda sig, pk, msg: lamport.verify(msg, sig, pk),
      hash_fn=lamport_hash_pk,
      subtree_size=2,
      num_layers=2
    )
    
  message = "Lamport purely string message"
  sig = ht.sign(message)
  self.assertTrue(ht.verify(sig))

  def test_hypertree_winternitz(self):
    w = 16
    ht = ext4.HyperTree(
      # Inject 'w' inline
      keygen_fn=lambda: winternitz.generate_keys(w),
      sign_fn=lambda sk, msg: winternitz.sign(msg, sk, w),
      verify_fn=lambda sig, pk, msg: winternitz.verify(msg, sig, pk, w),
      # Your merkle.py leaf_hash works perfectly for Winternitz's flat list
      hash_fn=merkle.leaf_hash, 
      subtree_size=2,
      num_layers=2
    )
    
    message = "Winternitz purely string message"
    sig = ht.sign(message)
    self.assertTrue(ht.verify(sig))

  def test_tree_regeneration_logic(self):
    w = 16
    ht = ext4.HyperTree(
      keygen_fn=lambda: winternitz.generate_keys(w),
      sign_fn=lambda sk, msg: winternitz.sign(msg, sk, w),
      verify_fn=lambda sig, pk, msg: winternitz.verify(msg, sig, pk, w),
      hash_fn=merkle.leaf_hash,
      subtree_size=2,
      num_layers=2
    )
    
    # Subtree capacity is 2. The 3rd message triggers layer regeneration.
    self.assertTrue(ht.verify(ht.sign("Message 1")))
    self.assertTrue(ht.verify(ht.sign("Message 2")))
    
    sig3 = ht.sign("Message 3")
    self.assertTrue(ht.verify(sig3))
    
    # Verify the top layer advanced to its next key
    self.assertEqual(sig3["key_indices"][1], 1)

if __name__ == "__main__":
  unittest.main()