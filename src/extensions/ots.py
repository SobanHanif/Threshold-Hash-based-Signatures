"""one time signature abstraction for benchmarking ease
"""

import hashlib
from typing import Any, Protocol, runtime_checkable

import lamport
import winternitz


@runtime_checkable
class OTS(Protocol):
    name: str

    def keygen(self) -> tuple[Any, Any]: ...
    def sign(self, message: str, sk: Any) -> list[bytes]: ...
    def verify(self, message: str, sig: list[bytes], pk: Any) -> bool: ...

    # lamports SKs are list of pairs which cant be XOR shared so need flatten/unflatten fns
    def flatten_sk(self, sk: Any) -> list[bytes]: ...
    def unflatten_sk(self, flat: list[bytes]) -> Any: ...

    # merkle leaves are scheme specifc as PK structures are different
    def leaf_hash(self, pk: Any) -> bytes: ...

    def share_element_size(self) -> int: ...


class WinternitzOTS:
    # WOTS wrapper

    def __init__(self, w: int = 16):
        if w < 2 or (w & (w - 1)) != 0:
            raise ValueError(f"w must be a power of 2 >= 2, instead received {w}")
        self.w = w
        self.name = f"Winternitz(w={w})"

    def keygen(self):
        sk, pk = winternitz.generate_keys(self.w)
        if sk is None:
            raise RuntimeError("winternitz.generate_keys failed")
        return sk, pk

    def sign(self, message, sk):
        return winternitz.sign(message, sk, self.w)

    def verify(self, message, sig, pk):
        return winternitz.verify(message, sig, pk, self.w)

    def flatten_sk(self, sk):
        return list(sk)

    def unflatten_sk(self, flat):
        return list(flat)

    def leaf_hash(self, pk):
        # old version:
        # return hashlib.sha256(b"".join(pk)).digest()
        #
        # optimisation 2: hash incrementally instead of joining all chains first
        h = hashlib.sha256()
        for part in pk:
            h.update(part)
        return h.digest()

    def share_element_size(self):
        return 32


class LamportOTS:
    ## lamport wrapper

    BITS = 256

    def __init__(self):
        self.name = "Lamport"

    def keygen(self):
        return lamport.generate_keys()

    def sign(self, message, sk):
        return lamport.sign(message, sk)

    def verify(self, message, sig, pk):
        return lamport.verify(message, sig, pk)

    def flatten_sk(self, sk):
        flat = []
        for pair in sk:
            flat.append(pair[0])
            flat.append(pair[1])
        return flat

    def unflatten_sk(self, flat):
        if len(flat) != 2 * self.BITS:
            raise ValueError(f"expected {2*self.BITS} got {len(flat)}")
        return [[flat[2 * i], flat[2 * i + 1]] for i in range(self.BITS)]

    def leaf_hash(self, pk):
        # for reference -> pk is list of [h0, h1] pairs
        # old version:
        # parts = []
        # for pair in pk:
        #     parts.append(pair[0])
        #     parts.append(pair[1])
        # return hashlib.sha256(b"".join(parts)).digest()
        #
        # optimisation 2: hash incrementally instead of building a temporary bytes object
        h = hashlib.sha256()
        for pair in pk:
            h.update(pair[0])
            h.update(pair[1])
        return h.digest()

    def share_element_size(self):
        return 32
