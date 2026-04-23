import time
import lamport


def run_minimal_protocol(message, n_parties=5, n_leaves=4):
    start = time.time()
    state = lamport.merkle_keygen(n_parties, n_leaves)
    print(
        f"Minimal keygen (n={n_parties}, leaves={n_leaves}): "
        f"{time.time() - start:.4f}s"
    )

    leaf_idx = 0

    start = time.time()
    sig = lamport.merkle_sign(message, leaf_idx, state)
    print(
        f"Signing with standard coordinator flow on leaf {leaf_idx}: "
        f"{time.time() - start:.4f}s"
    )

    start = time.time()
    ok = lamport.merkle_verify(message, sig, state["root"])
    print(f"Verification against Merkle root: {time.time() - start:.4f}s")
    print(f"Minimal protocol valid: {ok}")


def main():
    msg = input("Message to sign: ").strip()
    if not msg:
        msg = "hello world"

    print("\n== Minimal Protocol: Standard Flow + Lamport Tree ==")
    run_minimal_protocol(msg)


if __name__ == "__main__":
    main()
