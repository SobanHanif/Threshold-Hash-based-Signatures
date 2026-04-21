#!/usr/bin/env python3

import time
from lamport import generate_keys
from threshold import split_secret_key
from party import Party
from coordinator import Coordinator


def main():
    parties = []
    start_time = time.time()
    sk, pk = generate_keys()
    print(f"Key gen: {time.time() - start_time:.4f} seconds")
    
    n_parties = int(input("Number of parties: "))
    start_time = time.time()

    # sk_shares = split_secret_key(sk, n_parties)

    # Create Party-object for every shares
    parties = [Party() for _ in range(n_parties)]
    
    # depreciated logic: for s in sk_shares:
    #    parties.append(Party(s))

    # Then Register each of the party in coordinator
    crd = Coordinator(pk)

    for p in parties:
        crd.add_party(p)
    
    print(f"Share splitting: {time.time() - start_time:.4f} seconds")

    msg = input("Message to sign: ").strip()
    if not msg:
        msg = "hello world I am in pain"

    start_time = time.time()
    finalSign = crd.sign(msg)

    #sig_shares = [sign(msg, share) for share in sk_shares]
    print(f"Signing + Combining: {time.time() - start_time:.4f} seconds")
    

    start_time = time.time()
    # Verify Final Signature against the Pk
    res = crd.verify_Signature(msg, finalSign)
    
    print(f"Verification: {time.time() - start_time:.4f} seconds")

    print(f"Valid: {res}")

if __name__ == "__main__":
    main()
