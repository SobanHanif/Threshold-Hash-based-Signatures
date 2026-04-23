# Threshold Hash-Based Signatures

This project is an implementation of threshold hash-based signatures, built
around Lamport one-time signatures. It starts from a minimal n-of-n
coordinator model from the assignment spec, with seperation extensions of k-of-n via
Merkle trees over subset public keys, a Merkle batching layer for Lamport, nested Merkle subtrees within the higher nodes of the Merkle Tree,
Winternitz OTS, and a simple peer-to-peer signing protocol.

The construction is loosely followed from
[Threshold Hash-Based Signatures (IACR CiC, Vol. 2, No. 2)](https://cic.iacr.org/p/2/2/24),
which is also an entry to the NIST Threshold Cryptography call.

The code is split into a **minimal** core (the assignment's minimal
project) and a set of **extensions** built on top of the same primitives.

## Implemented parts

| Feature | Spec item | Where |
|---|---|---|
| Lamport OTS (keygen / sign / verify) | Minimal | `src/minimal/lamport.py` |
| XOR secret-key sharing + signature combining | Minimal | `src/minimal/threshold.py` |
| Coordinator / Party n-of-n signing | Minimal | `src/minimal/coordinator.py`, `src/minimal/party.py` |
| k-of-n over k-of-k subtrees with a Merkle root | Extension 1 | `src/extensions/kofn.py` |
| Peer-to-peer signing (no fixed aggregator) | Extension 2 | `src/extensions/p2p.py` |
| Merkle tree over multiple Lamport leaves | Extension 3 | have to add |
| Merkle trees within higher layers of the tree whilst leaving leaves as Lamport nodes | Extension 4 | have to add |
| Winternitz OTS drop-in for the k-of-n machinery | Extension 5 | `src/extensions/winternitz.py`, `src/extensions/ots.py` |


## Layout

```
Proj/
├── README.md
├── requirements.txt
├── src/
│   ├── minimal/                # spec's minimal n-of-n project
│   │   ├── lamport.py          # Lamport OTS + Merkle-Lamport helpers
│   │   ├── threshold.py        # XOR split / reconstruct / combine
│   │   ├── party.py            # Party that holds one share
│   │   ├── coordinator.py      # Aggregator that drives the signing round
│   │   └── main.py             # Runnable demo (n-of-n + Merkle-Lamport)
│   └── extensions/
│       ├── ots.py              # Generic OTS Protocol + Lamport / Winternitz wrappers
│       ├── winternitz.py       # Winternitz OTS implementation
│       ├── kofn.py             # k-of-n scheme (subset enumeration + Merkle root)
│       ├── p2p.py              # Peer-to-peer signing rounds
│       └── ext1_ext5.py        # Runnable demo for Ext 1 + Ext 5
├── benchmarks/
│   ├── bench_kofn_wots.py      # Lamport vs Winternitz across (n, k, w)
│   └── bench_p2p.py            # Coordinator vs P2P overhead / delay / failure modes
└── tests/
    ├── _path.py                # Adds src/ folders onto sys.path for flat imports
    ├── minimal/                # Tests for the minimal project
    └── extensions/             # Tests for every extension
```

## Quick start

Python 3.9+. The core implementation uses the standard library, and the
benchmark scripts use the small extra dependency listed in `requirements.txt`.

```bash
# install benchmark dependency
pip install -r requirements.txt

# minimal demo (Lamport n-of-n + Merkle-Lamport)
python3 src/minimal/main.py

# extension demo (k-of-n with Winternitz)
python3 src/extensions/ext1_ext5.py

# run every test
python3 -m unittest discover -s tests -t .

# Extension 1 / 5 benchmark
python3 benchmarks/bench_kofn_wots.py

# Extension 2 benchmark
python3 benchmarks/bench_p2p.py
```

## Tests

The tests mirror the source split. Everything runs under `unittest discover`
from the project root.

| File | What it covers |
|---|---|
| `tests/minimal/test_lamport.py` | Lamport round-trip, tampered message, wrong public key |
| `tests/minimal/test_coordinator.py` | Coordinator input validation, share requests, end-to-end signing with bytes and str messages |
| `tests/minimal/test_merkle_lamport.py` | Merkle-Lamport round-trip, tamper detection, one-time-use guard |
| `tests/extensions/test_winternitz.py` | WOTS round-trip across `w ∈ {4, 16, 256}`, tamper, wrong pk |
| `tests/extensions/test_threshold_kofn.py` | k-of-n across every OTS scheme, subset rejection, reuse guard, bad auth paths |
| `tests/extensions/test_scheme_switch.py` | Same harness runs over Lamport and WOTS without any protocol changes |
| `tests/extensions/test_p2p.py` | 100-party P2P n-of-n round, unavailable parties, tampered messages, different initiators |

## Benchmarks

There are currently two benchmark scripts:

- `benchmarks/bench_kofn_wots.py` compares **Lamport** against
  **Winternitz** at `w ∈ {4, 16, 256}` for several `(n, k)` pairs and prints
  timings for keygen, signing, verification, and signature size.
- `benchmarks/bench_p2p.py` compares the original **Coordinator** model
  against the **P2P** model from Extension 2.

For Extension 1 and 5, `benchmarks/bench_kofn_wots.py` measures:

- `schemes`: list of `OTS` instances to run.
- `params`: list of `(n, k)` pairs.
- `message`: payload to sign.

To re-run with different parameters, edit those lists and run
`python3 benchmarks/bench_kofn_wots.py`. This is the script we used for the
"Benchmarking + Comparison" part of the report. In practice we mostly stuck to
small values of `n` and `k` while developing, because anything much bigger
starts getting expensive pretty quickly. More on that below.

For Extension 2, `benchmarks/bench_p2p.py` measures three things:

- **leader overhead vs coordinator** as `n` grows
- **latency sensitivity** by adding artificial delay to each party response
- **failure behaviour**, including the extra case where the initiator itself is unavailable

That second benchmark is less about raw crypto cost and more about protocol
behaviour, since both coordinator and P2P still use the same Lamport signing
and verification underneath.

## Design choices

A few design choices are worth calling out (more details and design choices in the report)

- **XOR additive sharing for the minimal scheme.** We used XOR because it is
  simple, easy to reason about, and enough for an n-of-n construction. The
  downside is obvious: if even one share is missing, signing fails. For this
  project that was acceptable, since actual fault tolerance is the whole point
  of the k-of-n extension.
- **Enumerate every `k`-subset for Extension 1.** The k-of-k-subtrees idea
  from the paper turns into `C(n, k)` different keypairs in code, which gets
  expensive fast. We still kept that structure because it is the cleanest
  direct implementation of the construction, and it makes the cost visible in
  the benchmarks instead of hiding it.
- **Generic OTS adapter (`ots.py`).** Both Lamport and Winternitz sit behind
  the same `OTS` interface, so the k-of-n code and the benchmark do not need
  to know which scheme is underneath. That made it much easier to compare the
  two without rewriting protocol code.
- **One `sys.path` hack instead of a package.** `tests/_path.py` and the
  benchmark script prepend `src/minimal` and `src/extensions` to `sys.path`
  so modules can just do `import lamport`. It is a bit ugly, but for this
  project it was the quickest way to keep the minimal and extension code split
  without spending extra time packaging everything properly.
