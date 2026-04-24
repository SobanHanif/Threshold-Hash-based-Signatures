import os
import sys
import time
import hashlib
from tabulate import tabulate

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MINIMAL = os.path.join(ROOT, "src", "minimal")
EXTENSIONS = os.path.join(ROOT, "src", "extensions")

for path in (ROOT, MINIMAL, EXTENSIONS):
    if path not in sys.path:
        sys.path.insert(0, path)

from src.extensions.ext4 import HyperTree, SubTree


# using lamport/winternitz kind of kills my memory
def mock_keygen():
    sk = b"secret"
    pk = b"public"
    return sk, pk

def mock_sign(sk, message):
    return hashlib.sha256(sk + message).digest()
# assume nothing is incorrect :3
def mock_verify(sig, pk, message):
    return True

def mock_hash(pk):
    return hashlib.sha256(pk).digest()


# calculating sizes
def calculate_byte_size(obj):
    if isinstance(obj, bytes):
        return len(obj)
    elif isinstance(obj, str):
        return len(obj.encode())
    elif isinstance(obj, int):
        return 4  # Standard 4-byte integer
    elif isinstance(obj, list):
        return sum(calculate_byte_size(x) for x in obj)
    elif isinstance(obj, dict):
        return sum(calculate_byte_size(v) for v in obj.values())
    return 0


def main():
    print("Running Extension 4 (Hypertree) Benchmarks\n")

    print("Property 1. Initial Setup Time")
    print("~~Comparing different tree structures that can sign the same number of messages messages~~\n")
    
    setup_headers = ["Structure", "Subtree Size", "Layers", "Total Capacity", "Setup Time (s)"]
    setup_table = []
    
    # subtree size vs layers
    # if layres = 1 we are basically testing a not hypertree
    # subtreesize^layers should all be equal
    configurations = [
        (16, 3),
        (64, 2),
        (4096, 1),
        (4, 7),
        (64 * 2, 2),
        (4096 * 4, 1),
    ]

    for size, layers in configurations:
        t0 = time.perf_counter()
        
        if layers == 1:
            tree = SubTree(mock_keygen, mock_sign, mock_hash, size)
            structure_name = "Flat Tree"
        else:
            tree = HyperTree(mock_keygen, mock_sign, mock_verify, mock_hash, size, layers)
            structure_name = "Hypertree " + str(layers)
            
        setup_time = time.perf_counter() - t0
        capacity = size ** layers
        
        setup_table.append([
            structure_name, size, layers, capacity, f"{setup_time:.6f}"
        ])

    print(tabulate(setup_table, headers=setup_headers, tablefmt="fancy_outline"))


    print("\nProperty 2. Signature Size")
    print("~~Comparing how adding layers impacts the final signature size~~\n")

    size_headers = ["Structure", "Subtree Size", "Layers", "Total Capacity", "Signature Size (Bytes)"]
    size_table = []

    for size, layers in configurations:
        if layers == 1:
            tree = SubTree(mock_keygen, mock_sign, mock_hash, size)
            _, sig, pk, path = tree.sign(b"test_message")
            
            sig_dict = {
                "message": b"test_message",
                "sigs": [sig],
                "pks": [pk],
                "key_indices": [0],
                "auth_paths": [path]
            }
            structure_name = "Flat Tree"
        else:
            tree = HyperTree(mock_keygen, mock_sign, mock_verify, mock_hash, size, layers)
            sig_dict = tree.sign(b"test_message")
            structure_name = "Hypertree " + str(layers)

        sig_size = calculate_byte_size(sig_dict)
        capacity = size ** layers

        size_table.append([
            structure_name, size, layers, capacity, sig_size
        ])

    print(tabulate(size_table, headers=size_headers, tablefmt="fancy_outline"))
    
    print("\n Property 3. Initial Memory")
    print("~~Comparing the data size of the trees in memory immediately after setup~~\n")

    def extract_subtree_state(st):
        if st is None: return None
        return {"sks": st._sks, "pks": st._pks, "levels": st._levels, "root": st.root}

    mem_headers = ["Structure", "Subtree Size", "Layers", "Total Capacity", "Memory Size (Bytes)"]
    mem_table = []

    for size, layers in configurations:
        if layers == 1:
            tree = SubTree(mock_keygen, mock_sign, mock_hash, size)
            state = extract_subtree_state(tree)
            structure_name = "Flat Tree"
        else:
            tree = HyperTree(mock_keygen, mock_sign, mock_verify, mock_hash, size, layers)
            state = {
                "layers": [extract_subtree_state(l) for l in tree._layers],
                "cpk": tree.cpk,
                "link_sigs": tree._link_sigs,
                "link_pks": tree._link_pks,
                "link_paths": tree._link_paths,
                "link_indices": tree._link_indices
            }
            structure_name = "Hypertree " + str(layers)

        mem_size = calculate_byte_size(state)
        capacity = size ** layers

        mem_table.append([structure_name, size, layers, capacity, f"{mem_size:,}"])

    print(tabulate(mem_table, headers=mem_headers, tablefmt="fancy_outline"))
if __name__ == "__main__":
    main()