import hashlib
import secrets
import os

# MOCK — DELETE BEFORE SUBMISSION. Replace imports with pwm.elgamal and pwm.signatures.

def generate_keypair():
    # Mock returns the same string for pub and priv so verify can check it easily
    key = secrets.token_hex(16)
    return key, key

def load_public(path):
    if not os.path.exists(path): return "mock_pub"
    with open(path, "r") as f: return f.read().strip()

def load_private(path):
    if not os.path.exists(path): return "mock_priv"
    with open(path, "r") as f: return f.read().strip()

def sign(message_bytes, priv):
    # Mock signature
    return hashlib.sha256(message_bytes + str(priv).encode()).digest()

def verify(message_bytes, signature, pub):
    # Mock verify
    expected = hashlib.sha256(message_bytes + str(pub).encode()).digest()
    return expected == signature


