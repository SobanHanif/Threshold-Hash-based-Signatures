#!/usr/bin/env python3

import time
from lamport import generate_keys, sign, verify
from threshold import split_secret_key, combine_signatures

def main():
    start_time = time.time()
    sk, pk = generate_keys()
    print(f"Key gen: {time.time() - start_time:.4f} seconds")

    n_parties = 3
    start_time = time.time()
    sk_shares = split_secret_key(sk, n_parties)
    print(f"Share splitting: {time.time() - start_time:.4f} seconds")

    msg = input("Message to sign: ").strip()
    if not msg:
        msg = "hello world I am in pain"

    start_time = time.time()
    sig_shares = [sign(msg, share) for share in sk_shares]
    print(f"Signing: {time.time() - start_time:.4f} seconds")
    
    start_time = time.time()
    combined_sig = combine_signatures(sig_shares)
    print(f"Signature combination: {time.time() - start_time:.4f} seconds")

    start_time = time.time()
    verify(msg, combined_sig, pk)
    print(f"Verification: {time.time() - start_time:.4f} seconds")

if __name__ == "__main__":
    main()
