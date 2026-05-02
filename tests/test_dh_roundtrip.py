import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pwm.dh_export import (
    generate_dh_params, generate_dh_keypair, compute_shared_secret, derive_session_key
)

def test_dh_roundtrip():
    print("Testing DH roundtrip...")
    # Generate small prime params for quick testing
    # RFC 3526 1536-bit prime could be hardcoded, but we use generator for correctness
    # We will generate a very small 512-bit prime to keep test fast
    q, alpha = generate_dh_params(512)
    
    a, A = generate_dh_keypair(q, alpha)
    b, B = generate_dh_keypair(q, alpha)
    
    secret_a = compute_shared_secret(B, a, q)
    secret_b = compute_shared_secret(A, b, q)
    
    assert secret_a == secret_b, "Shared secrets do not match!"
    
    session_key_a = derive_session_key(secret_a)
    session_key_b = derive_session_key(secret_b)
    
    assert session_key_a == session_key_b, "Session keys do not match!"
    assert len(session_key_a) == 32, "Session key length is not 32 bytes (256 bits)"
    
    print("DH roundtrip test passed!")

if __name__ == "__main__":
    test_dh_roundtrip()

