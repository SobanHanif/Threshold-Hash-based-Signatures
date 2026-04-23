#!/usr/bin/env python3
"""comparative benchmark: lamport vs winternitz across (n, k) and w
"""

import os
import sys
import time
from itertools import combinations

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MINIMAL = os.path.join(_ROOT, "src", "minimal")
_EXTENSIONS = os.path.join(_ROOT, "src", "extensions")
for path in (_MINIMAL, _EXTENSIONS):
    if path not in sys.path:
        sys.path.insert(0, path)

from kofn import kofn_keygen, kofn_sign, kofn_verify
from ots import LamportOTS, WinternitzOTS


def _sig_size_bytes(sig):
    total = 4
    for part in sig["ots_sig"]:
        total += len(part)
    for part in sig["subset_pk"]:
        if isinstance(part, (bytes, bytearray)):
            total += len(part)
        else:  # lamport pair
            total += sum(len(x) for x in part)
    for node in sig["auth_path"]:
        total += len(node)
    return total


def bench_once(ots, n, k, message):
    t0 = time.perf_counter()
    state = kofn_keygen(n, k, ots)
    t_keygen = time.perf_counter() - t0

    selected = list(next(iter(combinations(range(n), k))))

    t0 = time.perf_counter()
    sig = kofn_sign(selected, message, state)
    t_sign = time.perf_counter() - t0

    t0 = time.perf_counter()
    ok = kofn_verify(message, sig, state["root"], n, k, ots)
    t_verify = time.perf_counter() - t0

    assert ok, f"{ots.name} n={n} k={k} verification failed"
    return t_keygen, t_sign, t_verify, _sig_size_bytes(sig), len(state["subsets"])


def main():
    message = "threshold benchmark"
    schemes = [
        LamportOTS(),
        WinternitzOTS(w=4),
        WinternitzOTS(w=16),
        WinternitzOTS(w=256),
    ]
    params = [(3, 2), (5, 3), (6, 3), (7, 4)]

    print(f"Message: {message!r}\n")
    print("| Scheme | n | k | subsets | key generation time (s) | signing time (s) | verify time (s) | signature size (bytes) |")
    print("|--------|---|---|---------|-------------------------|------------------|-----------------|------------------------|")
    for ots in schemes:
        for n, k in params:
            t_kg, t_sg, t_vf, sz, ns = bench_once(ots, n, k, message)
            print(
                f"| {ots.name} | {n} | {k} | {ns} | "
                f"{t_kg:.4f} | {t_sg:.4f} | {t_vf:.4f} | {sz} |"
            )


if __name__ == "__main__":
    main()
