import random
import json
import os
import hashlib
from math import gcd

#to get SHA-256
def hash_vault_content(data) -> int:
    if isinstance(data, str):
        data = data.encode('utf-8')
    hash_hex = hashlib.sha256(data).hexdigest()
    return int(hash_hex, 16)
 
 
def sign_vault(data, private_key: int, p: int, alpha: int) -> tuple:

    m = hash_vault_content(data)
 
    while True:
        k = random.randint(2, p - 2)
        if gcd(k, p - 1) == 1:
            break
 
    r = pow(alpha, k, p)
 
    try:
        k_inv = pow(k, -1, p - 1)
        # for python version 
    except ValueError:
        return sign_vault(data, private_key, p, alpha)

    s = (k_inv * (m - private_key * r)) % (p - 1)
 
    if s == 0:
        return sign_vault(data, private_key, p, alpha)
    return (r, s)
 
 
def verify_vault(data, signature: tuple, public_key: int, p: int, alpha: int) -> bool:
    r, s = signature
 
    if not (0 < r < p):
        return False
    if not (0 < s < p - 1):
        return False
 
    m = hash_vault_content(data)
 
    left  = pow(alpha, m, p)
    # right (y^r * r^s) mod p
    right = (pow(public_key, r, p) * pow(r, s, p)) % p
 
    return left == right

# File integration
def sign_and_save_vault(vault_path: str, private_key: int, p: int, alpha: int):
    with open(vault_path, 'r') as f:
        vault_data = json.load(f)
 
    encrypted_content = vault_data.get("encrypted_vault", "")
    if not encrypted_content:
        raise ValueError("Vault file has no encrypted_vault field.")
 
    r, s = sign_vault(encrypted_content, private_key, p, alpha)
 
    vault_data["signature"] = {"r": r, "s": s}
 
    with open(vault_path, 'w') as f:
        json.dump(vault_data, f, indent=2)
 
    print("Vault signed successfully.")
 
 
def verify_and_open_vault(vault_path: str, public_key: int, p: int, alpha: int) -> dict:
    with open(vault_path, 'r') as f:
        vault_data = json.load(f)
 
    encrypted_content = vault_data.get("encrypted_vault", "")
    signature_data    = vault_data.get("signature", {})
 
    if not signature_data:
        raise ValueError("No signature found in vault vault may be corrupted.")
 
    r = signature_data["r"]
    s = signature_data["s"]
 
    is_valid = verify_vault(encrypted_content, (r, s), public_key, p, alpha)
 
    if not is_valid:
        raise PermissionError(
            "SIGNATURE VERIFICATION FAILED.\n"
        )
 
    print("Vault signature verified Safe access to open.")
    return vault_data