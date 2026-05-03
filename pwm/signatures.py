import random
import json
import os
import hashlib
from math import gcd

#to get SHA-256
def hash_vault_content(data) -> int:
    """
    Compute SHA-256 hash of vault content or bytes.
    Returns the hash as a large integer for ElGamal operations.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    hash_hex = hashlib.sha256(data).hexdigest()
    return int(hash_hex, 16)
 
 
# ─────────────────────────────────────────────
# CORE MODULE 3 FUNCTIONS
# ─────────────────────────────────────────────
 
def sign_vault(data, private_key: int, p: int, alpha: int) -> tuple:
    """
    Sign the data using ElGamal digital signature.
 
    Args:
        data          : the data to sign (str or bytes)
        private_key   : ElGamal private key x (from Module 1)
        p             : large prime from config
        alpha         : primitive root modulo p from config
 
    Returns:
        (r, s) signature tuple
    """
    m = hash_vault_content(data)
 
    # Pick a valid random k
    while True:
        k = random.randint(2, p - 2)
        if gcd(k, p - 1) == 1:
            break
 
    r = pow(alpha, k, p)
 
    # Use built-in pow for modular inverse (Python 3.8+)
    try:
        k_inv = pow(k, -1, p - 1)
    except ValueError:
        # Fallback if Python version is old or k isn't coprime (though we checked gcd)
        # For our purposes, pow(k, -1, p-1) is perfectly fine.
        return sign_vault(data, private_key, p, alpha)

    s = (k_inv * (m - private_key * r)) % (p - 1)
 
    if s == 0:
        return sign_vault(data, private_key, p, alpha)
 
    return (r, s)
 
 
def verify_vault(data, signature: tuple, public_key: int, p: int, alpha: int) -> bool:
    """
    Verify the ElGamal signature of the data.
    """
    r, s = signature
 
    if not (0 < r < p):
        return False
    if not (0 < s < p - 1):
        return False
 
    m = hash_vault_content(data)
 
    left  = pow(alpha, m, p)
    right = (pow(public_key, r, p) * pow(r, s, p)) % p
 
    return left == right

 
 
# ─────────────────────────────────────────────
# VAULT FILE INTEGRATION
# ─────────────────────────────────────────────
 
def sign_and_save_vault(vault_path: str, private_key: int, p: int, alpha: int):
    """
    Read the vault file, sign the encrypted_vault content,
    and write the signature back into the vault JSON.
 
    Called after every: add / update / delete operation.
    """
    with open(vault_path, 'r') as f:
        vault_data = json.load(f)
 
    encrypted_content = vault_data.get("encrypted_vault", "")
    if not encrypted_content:
        raise ValueError("Vault file has no encrypted_vault field.")
 
    r, s = sign_vault(encrypted_content, private_key, p, alpha)
 
    vault_data["signature"] = {"r": r, "s": s}
 
    with open(vault_path, 'w') as f:
        json.dump(vault_data, f, indent=2)
 
    print("[OK] Vault signed successfully.")
 
 
def verify_and_open_vault(vault_path: str, public_key: int, p: int, alpha: int) -> dict:
    """
    Read the vault file, verify the signature.
    If valid, return the vault data for further processing.
    If invalid, raise an exception and refuse to open.
 
    Called every time the vault is opened.
    """
    with open(vault_path, 'r') as f:
        vault_data = json.load(f)
 
    encrypted_content = vault_data.get("encrypted_vault", "")
    signature_data    = vault_data.get("signature", {})
 
    if not signature_data:
        raise ValueError("[!] No signature found in vault. Vault may be corrupted.")
 
    r = signature_data["r"]
    s = signature_data["s"]
 
    is_valid = verify_vault(encrypted_content, (r, s), public_key, p, alpha)
 
    if not is_valid:
        raise PermissionError(
            "[!!!] SIGNATURE VERIFICATION FAILED.\n"
            "      The vault has been tampered with. Refusing to open."
        )
 
    print("OK] Vault signature verified. Safe to open.")
    return vault_data