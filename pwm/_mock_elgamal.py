import json
import secrets
import os

# MOCK — DELETE BEFORE SUBMISSION. Replace imports with pwm.elgamal

def _get_q_alpha():
    path = "pwm/dh_params.json"
    if not os.path.exists(path):
        return 23, 5  # fallback small primes if not generated yet
    with open(path, "r") as f:
        data = json.load(f)
    return int(data["q"], 16), int(data["alpha"])

def generate_keypair():
    q, alpha = _get_q_alpha()
    # private key x
    x = secrets.randbelow(q - 2) + 2
    # public key y = alpha^x mod q
    y = pow(alpha, x, q)
    return str(y), str(x)

def load_public(path):
    if not os.path.exists(path): return 0
    with open(path, "r") as f: return int(f.read().strip())

def load_private(path):
    if not os.path.exists(path): return 0
    with open(path, "r") as f: return int(f.read().strip())



