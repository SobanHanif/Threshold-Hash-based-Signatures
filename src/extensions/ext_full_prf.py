#!/usr/bin/env python3

import os
import sys
import time

# Path Setup
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MINIMAL = os.path.join(ROOT, "minimal")
EXTENSIONS = os.path.join(ROOT, "extensions")
for path in (MINIMAL, EXTENSIONS):
    if path not in sys.path:
        sys.path.insert(0, path)

import lamport
from prf_shares import merkle_keygen_prf


def run_prf_protocol(message, n_parties=5, n_leaves=4, server_party_id=0):
    start = time.time()
    state = merkle_keygen_prf(
        n_parties=n_parties,
        n_leaves=n_leaves,
        server_party_id=server_party_id,
    )
    print(
        f"PRF keygen (n={n_parties}, leaves={n_leaves}, server={server_party_id}): "
        f"{time.time() - start:.4f}s"
    )

    leaf_idx = 0

    start = time.time()
    sig = lamport.merkle_sign(message, leaf_idx, state)
    print(
        f"Signing with PRF-materialized shares on leaf {leaf_idx}: "
        f"{time.time() - start:.4f}s"
    )

    start = time.time()
    ok = lamport.merkle_verify(message, sig, state["root"])
    print(f"Verification against Merkle root: {time.time() - start:.4f}s")
    print(f"PRF variant valid: {ok}")


def main():
    msg = input("Message to sign: ").strip()
    if not msg:
        msg = "hello world"

    print("\n== Full Project Variant: PRF Shares + Lamport Tree ==")
    run_prf_protocol(msg)


if __name__ == "__main__":
    main()
