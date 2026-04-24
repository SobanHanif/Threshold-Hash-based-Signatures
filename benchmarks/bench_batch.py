#!/usr/bin/env python3
"""
Benchmarking Minimal Protocol vs Extension 3 (Batch Signing)
Measures overall execution time across different batch sizes.
"""

import os
import sys
import time
from tabulate import tabulate

# --- Path Setup ---
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MINIMAL = os.path.join(ROOT, "src", "minimal")
EXTENSIONS = os.path.join(ROOT, "src", "extensions")

for path in (ROOT, MINIMAL, EXTENSIONS):
    if path not in sys.path:
        sys.path.insert(0, path)

import lamport
from src.extensions.ext3 import BatchHandler
from party import Party
from coordinator import Coordinator


def run_benchmark():
    print("Benchmarking Minimal vs Extension 3 (Batch Signing)\n")
    
    total_messages = 100
    n_parties = 5
    batch_sizes = [2, 5, 10]
    
    headers = ["Protocol", "Total Messages", "Keys Used", "Total Time (s)", "Time per Msg (s)"]
    table = []
    # trying to use the lamport min protocol
    min_state = lamport.merkle_keygen(n_parties, total_messages)
    
    start_min = time.perf_counter()
    for i in range(total_messages):
        lamport.merkle_sign(f"msg_{i}".encode(), i, min_state)
    time_min = time.perf_counter() - start_min
    
    table.append([
        "Minimal Protocol", 
        total_messages, 
        total_messages, 
        f"{time_min:.4f}", 
        f"{time_min/total_messages:.6f}"
    ])

    for b_size in batch_sizes:
        keys_needed = total_messages // b_size
        print(f"Setting up Extension 3 (Batch Size {b_size}, Generating {keys_needed} keys)...")
        
        ext3_state = lamport.merkle_keygen(n_parties, keys_needed)
        
        # Wire the threshold signing logic into the BatchHandler
        def ext3_sig_fn(inner_root, key_id):
            parties = [
                Party(party_id=p, sk_share=ext3_state["party_shares"][p][key_id]) 
                for p in range(ext3_state["n_parties"])
            ]
            coord = Coordinator(ext3_state["leaf_public_keys"][key_id], parties)
            return coord.sign(inner_root)
            
        handler = BatchHandler(
            batch_size=b_size, 
            signature_fn=ext3_sig_fn, 
            pks=ext3_state["leaf_public_keys"]
        )
        
        print(f"Signing messages via Extension 3 (Batch Size {b_size})...")
        start_ext3 = time.perf_counter()
        for i in range(total_messages):
            handler.addMessage(f"msg_{i}".encode())
        time_ext3 = time.perf_counter() - start_ext3
        
        table.append([
            f"Extension 3 (Batch={b_size})", 
            total_messages, 
            keys_needed, 
            f"{time_ext3:.4f}", 
            f"{time_ext3/total_messages:.6f}"
        ])
        
    # ---------------------------------------------------------
    # Results
    # ---------------------------------------------------------
    print("\n## Overall Signing Time Comparison")
    print(tabulate(table, headers=headers, tablefmt="fancy_outline"))


if __name__ == "__main__":
    run_benchmark()