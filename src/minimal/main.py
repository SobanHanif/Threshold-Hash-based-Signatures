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
        f"Signing on leaf {leaf_idx}: "
        f"{time.time() - start:.4f}s"
    )

    start = time.time()
    ok = lamport.merkle_verify(message, sig, state["root"])
    print(f"Verification: {time.time() - start:.4f}s")
    print("verify(signed message):", ok)

    print(
        "verify(tampered message):",
        lamport.merkle_verify(message + "!", sig, state["root"]),
    )

    try:
        lamport.merkle_sign(message, leaf_idx, state)
        print("error: reuse should have been rejected")
    except RuntimeError as e:
        print(f"reuse rejected: {e}")


def main():
    msg = input("Message to sign: ").strip()
    if not msg:
        msg = "hello world"

    run_minimal_protocol(msg)


if __name__ == "__main__":
    main()
