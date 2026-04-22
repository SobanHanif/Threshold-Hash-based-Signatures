import lamport
import threshold
from party import Party
from p2p import P2PNetwork

N_PARTIES = 100

# Helper to generate keys, split into shares and buil P2P network
def setup_network():
    sk, pk = lamport.generate_keys()
    shares = threshold.split_secret_key(sk, N_PARTIES)

    parties = [Party(party_id=i, sk_share=shares[i]) for i in range(N_PARTIES)]
    network = P2PNetwork(parties, pk)
    return sk, pk, parties, network

# Test Signing Success
def test_successful_p2p_signing():
    _, pk, _, network = setup_network()
    message = "hello p2p"
    sig, ok = network.initiate_signing(0, message)
    
    assert ok is True, "Signing should succeed"
    assert len(sig) == 256, "Signature should be 256 elements long"
    assert lamport.verify(message, sig, pk) is True, "Signature should verify"

# Test n-of-on signing fails if a party is unavailable
def test_unavailable_party_fails():
    _, _, parties, network = setup_network()
    parties[2].set_availability(False)
    
    sig, ok = network.initiate_signing(0, "hello p2p")
    assert ok is False, "Signing should fail if a party is unavailable"
    assert sig is None, "No signature should be returned"

# Test combined signature fails verification if the message is changed
def test_tampered_message_fails():
    _, pk, _, network = setup_network()
    message = "hello p2p"
    sig, _ = network.initiate_signing(0, message)
    
    assert lamport.verify("tampered", sig, pk) is False, "Tampered message should fail verification"

# Test any party in the network intiates the signing
def test_different_initiator():
    _, pk, _, network = setup_network()
    message = "hello p2p"
    
    # Party 2 initiates instead of Party 0
    sig, ok = network.initiate_signing(2, message)
    assert ok is True, "Party 2 should be able to initiate"
    assert lamport.verify(message, sig, pk) is True

if __name__ == "__main__":
    import sys
    
    tests = [
        obj for name, obj in globals().items()
        if name.startswith("test_") and callable(obj)
    ]
    
    passed = 0
    failed = 0
    for test_fn in tests:
        try:
            test_fn()
            passed += 1
            print(f"PASS: {test_fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL: {test_fn.__name__}")
            if str(e):
                print(f"      {e}")
        except Exception as e:
            failed += 1
            print(f"ERROR: {test_fn.__name__} - {e}")
            
    print(f"\nRan {passed + failed} tests")
    if failed > 0:
        print(f"FAILED (failures={failed})")
        sys.exit(1)
    else:
        print("All Tests Passed")
