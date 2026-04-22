#!/usr/bin/env python3
"""benchmark extension 2 against the coordinator baseline
"""

import os
import sys
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MINIMAL = os.path.join(_ROOT, "src", "minimal")
_EXTENSIONS = os.path.join(_ROOT, "src", "extensions")
for path in (_MINIMAL, _EXTENSIONS):
    if path not in sys.path:
        sys.path.insert(0, path)

import lamport
import threshold
from coordinator import Coordinator
from party import Party
from p2p import P2PNetwork


class DelayedParty(Party):
    def __init__(self, *args, response_delay_s=0.0, **kwargs):
        super().__init__(*args, **kwargs)
        self.response_delay_s = response_delay_s

    def receive_sign_request(self, message):
        if self.response_delay_s > 0:
            time.sleep(self.response_delay_s)
        return super().receive_sign_request(message)


def build_parties(shares, response_delay_s=0.0):
    return [
        DelayedParty(
            party_id=i,
            sk_share=shares[i],
            response_delay_s=response_delay_s,
        )
        for i in range(len(shares))
    ]


def avg_time(fn, repeats):
    total = 0.0
    result = None
    for _ in range(repeats):
        t0 = time.perf_counter()
        result = fn()
        total += time.perf_counter() - t0
    return total / repeats, result


def setup_material(n):
    t0 = time.perf_counter()
    sk, pk = lamport.generate_keys()
    shares = threshold.split_secret_key(sk, n)
    setup_time = time.perf_counter() - t0
    return pk, shares, setup_time


def coordinator_sign_once(pk, shares, message, response_delay_s=0.0):
    parties = build_parties(shares, response_delay_s)
    coordinator = Coordinator(pk, parties)
    return coordinator.sign(message)


def p2p_sign_once(pk, shares, message, response_delay_s=0.0, initiator_id=0):
    parties = build_parties(shares, response_delay_s)
    network = P2PNetwork(parties, pk)
    return network.initiate_signing(initiator_id, message)


def baseline_scaling_row(n, message, repeats):
    pk, shares, setup_time = setup_material(n)

    coord_sign_t, coord_sig = avg_time(
        lambda: coordinator_sign_once(pk, shares, message), repeats
    )
    p2p_sign_t, p2p_result = avg_time(
        lambda: p2p_sign_once(pk, shares, message), repeats
    )

    p2p_sig, ok = p2p_result
    assert ok, f"p2p signing failed for n={n}"
    assert lamport.verify(message, coord_sig, pk), f"coordinator signature failed for n={n}"
    assert lamport.verify(message, p2p_sig, pk), f"p2p signature failed for n={n}"

    coord_verify_t, _ = avg_time(lambda: lamport.verify(message, coord_sig, pk), repeats)
    p2p_verify_t, _ = avg_time(lambda: lamport.verify(message, p2p_sig, pk), repeats)

    return {
        "n": n,
        "setup_time": setup_time,
        "coord_sign_time": coord_sign_t,
        "p2p_sign_time": p2p_sign_t,
        "coord_verify_time": coord_verify_t,
        "p2p_verify_time": p2p_verify_t,
        "p2p_overhead_pct": 100.0 * (p2p_sign_t - coord_sign_t) / coord_sign_t,
    }


def latency_row(n, message, repeats, delay_ms):
    pk, shares, _ = setup_material(n)
    delay_s = delay_ms / 1000.0

    coord_sign_t, coord_sig = avg_time(
        lambda: coordinator_sign_once(pk, shares, message, delay_s), repeats
    )
    p2p_sign_t, p2p_result = avg_time(
        lambda: p2p_sign_once(pk, shares, message, delay_s), repeats
    )

    p2p_sig, ok = p2p_result
    assert ok, f"p2p delayed signing failed for n={n}, delay={delay_ms}ms"
    assert lamport.verify(message, coord_sig, pk)
    assert lamport.verify(message, p2p_sig, pk)

    return {
        "delay_ms": delay_ms,
        "coord_sign_time": coord_sign_t,
        "p2p_sign_time": p2p_sign_t,
        "p2p_overhead_pct": 100.0 * (p2p_sign_t - coord_sign_t) / coord_sign_t,
    }


def failure_row(n, message, repeats):
    pk, shares, _ = setup_material(n)

    def coordinator_missing_party():
        parties = build_parties(shares)
        parties[-1].set_availability(False)
        coordinator = Coordinator(pk, parties)
        try:
            coordinator.sign(message)
            return True
        except ValueError:
            return False

    def p2p_missing_party():
        parties = build_parties(shares)
        parties[-1].set_availability(False)
        network = P2PNetwork(parties, pk)
        return network.initiate_signing(0, message)

    def p2p_missing_initiator():
        parties = build_parties(shares)
        parties[0].set_availability(False)
        network = P2PNetwork(parties, pk)
        return network.initiate_signing(0, message)

    coord_fail_t, coord_fail_result = avg_time(coordinator_missing_party, repeats)
    p2p_fail_t, p2p_fail_result = avg_time(p2p_missing_party, repeats)
    p2p_initiator_t, p2p_initiator_result = avg_time(p2p_missing_initiator, repeats)

    assert coord_fail_result is False, f"coordinator missing-party case did not fail for n={n}"
    assert p2p_fail_result == (None, False), f"p2p missing-party case did not fail for n={n}"
    assert p2p_initiator_result == (None, False), f"p2p initiator-fail case did not fail for n={n}"

    return {
        "n": n,
        "coord_missing_party_time": coord_fail_t,
        "p2p_missing_party_time": p2p_fail_t,
        "p2p_missing_initiator_time": p2p_initiator_t,
    }


def main():
    message = "p2p benchmark"
    scaling_params = [4, 8, 16, 32, 64, 100]
    latency_n = 16
    latency_delays_ms = [0, 1, 5, 10, 50]
    failure_params = [16, 100]

    scaling_repeats = 20
    latency_repeats = 5
    failure_repeats = 20

    print(f"Message: {message!r}\n")

    print("## 1) Leader overhead vs coordinator")
    print(f"Average over {scaling_repeats} runs per row.\n")
    print("| n | setup key+shares (s) | coordinator sign (s) | p2p sign (s) | p2p overhead (%) | coordinator verify (s) | p2p verify (s) |")
    print("|---|----------------------|----------------------|---------------|------------------|------------------------|----------------|")
    for n in scaling_params:
        row = baseline_scaling_row(n, message, scaling_repeats)
        print(
            f"| {row['n']} | "
            f"{row['setup_time']:.6f} | "
            f"{row['coord_sign_time']:.6f} | "
            f"{row['p2p_sign_time']:.6f} | "
            f"{row['p2p_overhead_pct']:.2f} | "
            f"{row['coord_verify_time']:.6f} | "
            f"{row['p2p_verify_time']:.6f} |"
        )

    print("\n## 2) Latency sensitivity")
    print(
        f"Artificial delay is inserted into every party response. "
        f"n={latency_n}, average over {latency_repeats} runs.\n"
    )
    print("| delay per party (ms) | coordinator sign (s) | p2p sign (s) | p2p overhead (%) |")
    print("|----------------------|----------------------|---------------|------------------|")
    for delay_ms in latency_delays_ms:
        row = latency_row(latency_n, message, latency_repeats, delay_ms)
        print(
            f"| {row['delay_ms']} | "
            f"{row['coord_sign_time']:.6f} | "
            f"{row['p2p_sign_time']:.6f} | "
            f"{row['p2p_overhead_pct']:.2f} |"
        )

    print("\n## 3) Failure behaviour")
    print(f"Average over {failure_repeats} runs per row.\n")
    print("| n | coordinator missing party (s) | p2p missing non-initiator (s) | p2p missing initiator (s) |")
    print("|---|--------------------------------|------------------------------|---------------------------|")
    for n in failure_params:
        row = failure_row(n, message, failure_repeats)
        print(
            f"| {row['n']} | "
            f"{row['coord_missing_party_time']:.6f} | "
            f"{row['p2p_missing_party_time']:.6f} | "
            f"{row['p2p_missing_initiator_time']:.6f} |"
        )


if __name__ == "__main__":
    main()
