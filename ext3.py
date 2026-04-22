"""

Extension 3: Use Merkle trees on the Lamport tree leaves to buffer then batch sign messages efficiently and update the 
verification algorithm to support this.

Impl: merkle leaves become H(CPK) per CPK of message, CPK of batch messages is a merkle tree of individual CPKS

"""
import hashlib
import secrets
import merkle

class BatchHandler:
  """ Handles batching logic """
  def __init__(self, batch_size: int, signature_fn, pks: list):
    """
    batch_size: how many messages per batch (we can force this to be a power of 2)
    signature_fn: function(message, key_id) -> existing signature function (agnostic of lamport/winternitz)
    pks: list of all public keys, one per outer leaf
    """
    # merkle.py should alr handle duping
    # if batch_size & (batch_size - 1) != 0:
    #   raise ValueError("batch_size must be a power of 2")
    
    # firstly build our merkle tree for PKs
    outer_leaves = [merkle.leaf_hash(pk) for pk in pks]
    outer_tree_levels = merkle.build_merkle(outer_leaves)
    
    self.batch_size = batch_size
    self.outer_levels = outer_tree_levels
    self.pks = pks
    self.signature_fn = signature_fn

    # all messages:
    self.buffer = []
    # tracks the current secret key we're using
    self.current_key_id   = 0
    # tracks which batches are processed w/ relevant info
    self.completed_batches = []
  
  def addMessage(self, message):
    """
    Add a message to the current batch, creates a new inner tree when full (empties buffer)
    """
    self.buffer.append(message)
    if len(self.buffer) == self.batch_size:
      # flushes when full
      self._reset_buffer()

  def _reset_buffer(self):
    if self.current_key_id >= len(self.pks):
      raise RuntimeError("all keypairs exhausted!")
    
    messages = list(self.buffer)
    key_id = self.current_key_id
    
    inner_levels, inner_root = self._build_inner_tree(messages)

    # sign
    curr_sig = self.signature_fn(inner_root, key_id)
    
    outer_path = merkle.merkle_auth_path(self.outer_levels, key_id)
    
    """
    key_id: tracking which S/P K pair was used for this batch
    messages: stores all the messages we ended up using in this batch
    inner_levels: just same as levels in a merkle tree
    inner_root: root of the merkle tree
    signature: self explanatory.
    pk: self explanatory.
    outer_path: path/proof from the outer tree. recall the outer tree is pregenerated and is a lookup of existing public keys.
    """

    self.completed_batches.append({
      "key_id": key_id,
      "messages": messages,
      "inner_levels": inner_levels,
      "inner_root": inner_root,
      "signature": curr_sig,
      "pk": self.pks[key_id],
      "outer_path": outer_path,
    })
    
    self.current_key_id += 1
    
    # kill buffer
    self.buffer = []
  def get_proof(self, batch_index: int, message_index: int) -> dict:
    """
    Uses inbuilt proof/path rebuilder from merkle.
    """
    batch = self.completed_batches[batch_index]

    inner_path = merkle.merkle_auth_path(batch["inner_levels"], message_index)

    return {
      "message": batch["messages"][message_index],
      "message_index": message_index,
      "inner_path": inner_path,
      "inner_root": batch["inner_root"],
      "key_id": batch["key_id"],
      "signature": batch["signature"],
      "pk": batch["pk"],
      "outer_path": batch["outer_path"],
    }
  
  def _build_inner_tree(self, messages: list):
    """
    Build a Merkle tree over a batch of messages. Reuses merkle logic
    """
    # hash each message to get leaves
    leaves = [hashlib.sha256(m).digest() for m in messages]
    
    # reuse existing merkle builder
    levels = merkle.build_merkle(leaves)
    root = levels[-1][0]
    
    return levels, root
  

  ### VERIFIERS

  def batch_verify(self, proof: dict, outer_root, verify_fn) -> bool:
    """
    Verify a single message from a batch signature.
    Note proof should come from batchhandler's getproof(), outer_root is the CPK from all the preset public keys
    """
    message = proof["message"]
    message_index = proof["message_index"]
    inner_path = proof["inner_path"]
    inner_root = proof["inner_root"]
    key_id = proof["key_id"]
    signature = proof["signature"]
    pk = proof["pk"]
    outer_path = proof["outer_path"]
    
    # first verification: show the root is a representative of our message
    inner_leaf = hashlib.sha256(message).digest()
    recomputed_inner_root = merkle.verify_merkle(
      inner_leaf, message_index, inner_path, inner_root
    )

    if (not recomputed_inner_root): 
      return False
   
    if not verify_fn(inner_root, signature, pk):
      return False
  
    outer_leaf = merkle.leaf_hash(pk)
    # verify outer root (aka the CPK)
    return merkle.verify_merkle(outer_leaf, key_id, outer_path, outer_root)
  


