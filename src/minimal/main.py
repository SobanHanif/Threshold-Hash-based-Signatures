import time
import lamport
import threshold
from coordinator import Coordinator
from party import Party


def run_standard_protocol(message, n_parties=4):
    start = time.time()
    sk, pk = lamport.generate_keys()
    print(f"Lamport keygen: {time.time() - start:.4f}s")

    start = time.time()
    shares = threshold.split_secret_key(sk, n_parties)
    parties = [Party(party_id=i, sk_share=shares[i]) for i in range(n_parties)]
    coordinator = Coordinator(pk, parties)
    print(f"Share splitting: {time.time() - start:.4f}s")

    start = time.time()
    signature = coordinator.sign(message)
    print(f"Coordinator signing: {time.time() - start:.4f}s")

    start = time.time()
    ok = coordinator.verify_signature(message, signature)
    print(f"Coordinator verification: {time.time() - start:.4f}s")
    print(f"Coordinator protocol valid: {ok}")


def run_merkle_lamport(message, n_parties=5, n_leaves=4):
    start = time.time()
    state = lamport.merkle_keygen(n_parties, n_leaves)
    print(
        f"Merkle Lamport keygen (n={n_parties}, leaves={n_leaves}): "
        f"{time.time() - start:.4f}s"
    )

    leaf_idx = 0
    start = time.time()
    sig = lamport.merkle_sign(message, leaf_idx, state)
    print(f"Merkle Lamport signing with leaf {leaf_idx}: {time.time() - start:.4f}s")

    start = time.time()
    ok = lamport.merkle_verify(message, sig, state["root"])
    print(f"Merkle Lamport verification: {time.time() - start:.4f}s")
    print(f"Merkle Lamport valid: {ok}")


def main():
    msg = input("Message to sign: ").strip()
    if not msg:
        msg = "hello world"

    print("\n== Standard Party Coordinator Protocol ==")
    run_standard_protocol(msg)

    print("\n== Merkle Tree on Lamport Signature ==")
    run_merkle_lamport(msg)


if __name__ == "__main__":
    main()
