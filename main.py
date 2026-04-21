#!/usr/bin/env python3

import time
from threshold import kofn_keygen, kofn_sign, kofn_verify


def main():
    w = 16
    n = 5
    k = 3
# for benchmarking & error testing (? soban ? give thoughts when u read this)
    start = time.time()
    state = kofn_keygen(n, k, w)
    print(f"k-of-n keygen (n={n}, k={k}, subsets={len(state['subsets'])}): "
          f"{time.time() - start:.4f} seconds")

    msg = input("Message to sign: ").strip()
    if not msg:
        msg = "hello world I am in pain xdddddddddd"

    # pick any k of the n parties
    selected = [0, 2, 4]

    start = time.time()
    sig = kofn_sign(selected, msg, state)
    print(f"Signing with parties {selected}: {time.time() - start:.4f} seconds")

    start = time.time()
    ok = kofn_verify(msg, sig, state["root"], n, k, w)
    print(f"Verification: {time.time() - start:.4f} seconds")
    print("verify(signed message):", ok)

    # check tampered with message fails
    print("verify(tampered message):",
          kofn_verify(msg + "!", sig, state["root"], n, k, w))

    # a different but still valid k-subset should work
    other = [1, 2, 3]
    sig2 = kofn_sign(other, msg, state)
    print(f"verify(other subset {other}):",
          kofn_verify(msg, sig2, state["root"], n, k, w))

    # too few parties must fail 
    try:
        kofn_sign([0, 1], msg, state)
        print("error: this should NOT happen dawg, too little parties")
    except ValueError as e:
        print(f"too little parties -> error: {e}")


if __name__ == "__main__":
    main()
