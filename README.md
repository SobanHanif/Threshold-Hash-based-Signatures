# Threshold-Hash-based-Signatures

## ibi - changes for extension 5 & 1


## Extension 5 - WOTS implemented

- lamport swapped for WOTS
- `threshold.py`:
  - `split_secret_key(sk, n)` now splits  WOTS sk into n XOR shares
  - `combine_signatures(sig_shares, msg, w)` XORs the shares to rebuild sk, then calls WOTS
  - hash chains arent homomorphic under XOR so chaining has to happen after reconstruction & not before
- `main.py` uses winternitz now

## Extension 1 - k-of-n via k-of-k subtrees

- any k of the n parties can now produce a valid signature
- design: enumerates every k-subset, each gets its own WOTS keypair, sk split into k XOR shares among that subsets members
- merkle tree over all subset pks -> root is the global pk
- in `threshold.py` added:
  - `_leaf_hash`, `_build_merkle`, `_merkle_auth_path`, `_verify_merkle` helpers for merkle w/ sha256
  - `kofn_keygen(n, k, w)` - generates all subset keypairs + splits + tree, gives each party their shares
  - `kofn_sign(selected, msg, state)` - picks the subset, retrieves its k shares, runs existing combine_signatures function, attaches auth path
  - `kofn_verify(msg, sig, root, n, k, w)` - verifies the WOTS sig under the subsets pk, then checks the merkle path up to the root
- signature carries: `subset_idx`, `subset_pk`, `wots_sig`, `auth_path`
- verifier only needs merkle root
- error handling for less than k parties/ tampered message 

## Running
- main.py for simple usage case
- bench.py for benchmark between wots and lamport scheme


