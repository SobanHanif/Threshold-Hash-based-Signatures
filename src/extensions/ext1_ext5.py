#!/usr/bin/env python3

import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_MINIMAL = os.path.join(os.path.dirname(_HERE), "minimal")
if _MINIMAL not in sys.path:
    sys.path.insert(0, _MINIMAL)

from kofn import kofn_keygen, kofn_sign, kofn_verify
from ots import WinternitzOTS


def main():
    ots = WinternitzOTS(w=16)
    n = 5
    k = 3

    start = time.time()
    state = kofn_keygen(n, k, ots)
    print(
        f"k-of-n keygen (n={n}, k={k}, subsets={len(state['subsets'])}): "
        f"{time.time() - start:.4f}s"
    )

    msg = input("Message to sign: ").strip()
    if not msg:
        msg = "hello world I am in pain xdddddddddd"

    selected = [0, 2, 4]
    start = time.time()
    sig = kofn_sign(selected, msg, state)
    print(f"Signing with parties {selected}: {time.time() - start:.4f}s")

    start = time.time()
    ok = kofn_verify(msg, sig, state["root"], n, k, ots)
    print(f"Verification: {time.time() - start:.4f}s")
    print("verify(signed message):", ok)

    print(
        "verify(tampered message):",
        kofn_verify(msg + "!", sig, state["root"], n, k, ots),
    )

    other = [1, 2, 3]
    sig2 = kofn_sign(other, msg, state)
    print(
        f"verify(other subset {other}):",
        kofn_verify(msg, sig2, state["root"], n, k, ots),
    )

    try:
        kofn_sign([0, 1], msg, state)
        print("error: too-few-parties sign should have raised")
    except ValueError as e:
        print(f"too few parties -> rejected: {e}")

    try:
        kofn_sign(selected, msg, state)
        print("error: reuse should have been rejected")
    except RuntimeError as e:
        print(f"reuse rejected: {e}")


if __name__ == "__main__":
    main()
