# Threshold-Hash-based-Signatures

## ibi - changes for extension 5 & 1


## Extension 5 - WOTS implemented

- lamport swapped for WOTS
- `src/minimal/threshold.py`:
  - `split_secret_key(sk, n)` splits WOTS/Lamport secret material into XOR shares
- `src/extensions/kofn.py`:
  - `ots_combine_signature(sig_shares, msg, ots)` XORs the shares to rebuild sk, then calls the OTS signer
  - hash chains arent homomorphic under XOR so chaining has to happen after reconstruction & not before
- `src/extensions/ext1_ext5.py` runs the Winternitz-based extension 1/5 demo

## Extension 1 - k-of-n via k-of-k subtrees

- any k of the n parties can now produce a valid signature
- design: enumerates every k-subset, each gets its own WOTS keypair, sk split into k XOR shares among that subsets members
- merkle tree over all subset pks -> root is the global pk
- in `src/extensions/kofn.py` added:
  - `_build_merkle`, `_merkle_auth_path`, `_verify_merkle` helpers for merkle w/ sha256
  - `kofn_keygen(n, k, w)` - generates all subset keypairs + splits + tree, gives each party their shares
  - `kofn_sign(selected, msg, state)` - picks the subset, retrieves its k shares, runs `ots_combine_signature`, attaches auth path
  - `kofn_verify(msg, sig, root, n, k, w)` - verifies the WOTS sig under the subsets pk, then checks the merkle path up to the root
- signature carries: `subset_idx`, `subset_pk`, `wots_sig`, `auth_path`
- verifier only needs merkle root
- error handling for less than k parties/ tampered message 

## Running
- `src/minimal/main.py` runs the simpler baseline demos:
  - standard coordinator/party signing with Lamport shares
  - merkle-tree-backed Lamport signing
- `src/extensions/ext1_ext5.py` runs the extension 1/5 Winternitz demo
- baseline code now lives under `src/minimal/`
- extension code now lives under `src/extensions/`
- tests now live under `tests/` and can be run with `python3 -m unittest discover tests`


