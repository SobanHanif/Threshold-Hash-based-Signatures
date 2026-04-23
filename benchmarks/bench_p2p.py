#!/usr/bin/env python3
"""
Benchmarking for extension 2
"""

import os
import sys
import time
from tabulate import tabulate

# Path Setup
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (os.path.join(ROOT, "src", "minimal"), os.path.join(ROOT, "src", "extensions")):
    if path not in sys.path:
        sys.path.insert(0, path)

import lamport
import threshold
from coordinator import Coordinator
from party import Party
from p2p import P2PNetwork


# Executes a function multiple times and returns the average duration and last result
def time_it(fn, repeats, *args):
    start_time = time.perf_counter()
    
    result = None
    for _ in range(repeats):
        result = fn(*args)
        
    end_time = time.perf_counter()
    average_duration = (end_time - start_time) / repeats
    
    return average_duration, result

# Builds parties and applies network latency
def get_parties(shares, delay_ms=0):
    parties = []
    for i in range(len(shares)):
        new_party = Party(party_id=i, sk_share=shares[i])
        parties.append(new_party)
    
    if delay_ms > 0:
        delay_seconds = delay_ms / 1000.0
        
        for p in parties:
            original_req = p.receive_sign_request
            
            def wrap_request(msg, req_func=original_req):
                time.sleep(delay_seconds)
                return req_func(msg)
                
            p.receive_sign_request = wrap_request
            
    return parties


def main():
    print("Running P2P Benchmarking\n")

    # ---------------------------------------------------------
    # 1. Leader overhead vs coordinator
    # ---------------------------------------------------------
    repeats = 20
    print("## 1) Leader overhead vs coordinator")
    print(f"Average over {repeats} runs per row.\n")

    headers_1 = ["n", "Setup (s)", "Coord Sign (s)", "P2P Sign (s)", "Overhead (%)", "Coord Vfy (s)", "P2P Vfy (s)"]
    table_1 = []

    for n in [4, 8, 16, 32, 64, 100]:
        t0 = time.perf_counter()
        sk, pk = lamport.generate_keys()
        shares = threshold.split_secret_key(sk, n)
        setup_t = time.perf_counter() - t0

        parties = get_parties(shares)
        coord = Coordinator(pk, parties)
        net = P2PNetwork(parties, pk)

        coord_sign_t, coord_sig = time_it(coord.sign, repeats, "p2p benchmark")
        p2p_sign_t, p2p_result = time_it(net.initiate_signing, repeats, 0, "p2p benchmark")
        
        p2p_sig = p2p_result[0]
        is_ok = p2p_result[1]

        # Sanity check
        assert is_ok, f"P2P signing failed for n={n}"
        assert lamport.verify("p2p benchmark", coord_sig, pk), f"Coord verification failed for n={n}"
        assert lamport.verify("p2p benchmark", p2p_sig, pk), f"P2P verification failed for n={n}"

        coord_vfy_t, _ = time_it(lamport.verify, repeats, "p2p benchmark", coord_sig, pk)
        p2p_vfy_t, _ = time_it(lamport.verify, repeats, "p2p benchmark", p2p_sig, pk)
        
        overhead = 100.0 * (p2p_sign_t - coord_sign_t) / coord_sign_t

        table_1.append([
            n, 
            f"{setup_t:.6f}", 
            f"{coord_sign_t:.6f}", 
            f"{p2p_sign_t:.6f}", 
            f"{overhead:.2f}", 
            f"{coord_vfy_t:.6f}", 
            f"{p2p_vfy_t:.6f}"
        ])

    print(tabulate(table_1, headers=headers_1, tablefmt="fancy_outline"))


    # ---------------------------------------------------------
    # 2. Latency sensitivity
    # ---------------------------------------------------------
    latency_n = 16
    latency_repeats = 5
    print(f"\n\n## 2) Latency sensitivity")
    print(f"Artificial delay is inserted into every party response. n={latency_n}, average over {latency_repeats} runs.\n")

    headers_2 = ["Delay (ms)", "Coord Sign (s)", "P2P Sign (s)", "Overhead (%)"]
    table_2 = []

    sk, pk = lamport.generate_keys()
    shares = threshold.split_secret_key(sk, latency_n)

    for delay_ms in [0, 1, 5, 10, 50]:
        parties = get_parties(shares, delay_ms)
        coord = Coordinator(pk, parties)
        net = P2PNetwork(parties, pk)

        coord_sign_t, _ = time_it(coord.sign, latency_repeats, "p2p benchmark")
        p2p_sign_t, _ = time_it(net.initiate_signing, latency_repeats, 0, "p2p benchmark")
        
        overhead = 100.0 * (p2p_sign_t - coord_sign_t) / coord_sign_t

        table_2.append([
            delay_ms, 
            f"{coord_sign_t:.6f}", 
            f"{p2p_sign_t:.6f}", 
            f"{overhead:.2f}"
        ])
        
    print(tabulate(table_2, headers=headers_2, tablefmt="fancy_outline"))


    # ---------------------------------------------------------
    # 3. Failure behaviour
    # ---------------------------------------------------------
    failure_repeats = 20
    print(f"\n\n## 3) Failure behaviour")
    print(f"Average over {failure_repeats} runs per row.\n")

    headers_3 = ["n", "Coord Missing Party (s)", "P2P Missing Party (s)", "P2P Missing Initiator (s)"]
    table_3 = []

    for n in [16, 100]:
        sk, pk = lamport.generate_keys()
        shares = threshold.split_secret_key(sk, n)

        # Setup standard missing party
        parties = get_parties(shares)
        parties[-1].set_availability(False) 
        
        coord = Coordinator(pk, parties)
        net = P2PNetwork(parties, pk)

        def trigger_coord_fail():
            try:
                coord.sign("p2p benchmark")
            except ValueError:
                pass

        coord_miss_t, _ = time_it(trigger_coord_fail, failure_repeats)
        p2p_miss_t, _ = time_it(net.initiate_signing, failure_repeats, 0, "p2p benchmark")

        # Setup missing initiator
        parties[0].set_availability(False)
        p2p_init_fail_t, _ = time_it(net.initiate_signing, failure_repeats, 0, "p2p benchmark")

        table_3.append([
            n, 
            f"{coord_miss_t:.6f}", 
            f"{p2p_miss_t:.6f}", 
            f"{p2p_init_fail_t:.6f}"
        ])

    print(tabulate(table_3, headers=headers_3, tablefmt="fancy_outline"))


if __name__ == "__main__":
    main()
