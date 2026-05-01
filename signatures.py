import random
import json
import os
import hashlib
from math import gcd
from keygen import mod_inverse

#to get SHA-256
def hash_vault_content(vault_content: str) -> int:
    """
    Compute SHA-256 hash of vault content string.
    Returns the hash as a large integer for ElGamal operations.
    """
    hash_hex = hashlib.sha256(vault_content.encode('utf-8')).hexdigest()
    return int(hash_hex, 16)
 
 
# ─────────────────────────────────────────────
# CORE MODULE 3 FUNCTIONS
# ─────────────────────────────────────────────
 
def sign_vault(vault_content: str, private_key: int, p: int, alpha: int) -> tuple:
    """
    Sign the vault content using ElGamal digital signature.
 
    Args:
        vault_content : the encrypted vault string (from vault.json "encrypted_vault")
        private_key   : ElGamal private key x (from Module 1)
        p             : large prime from config
        alpha         : primitive root modulo p from config
 
    Returns:
        (r, s) signature tuple
 
    ElGamal Signing:
        m = SHA-256(vault_content) as integer
        pick random k where gcd(k, p-1) == 1
        r = alpha^k mod p
        s = k_inverse * (m - x * r) mod (p - 1)
    """
    # Step 1: Hash the vault content
    m = hash_vault_content(vault_content)
 
    # Step 2: Pick a valid random k
    while True:
        k = random.randint(2, p - 2)
        if gcd(k, p - 1) == 1:
            break
 
    # Step 3: Compute r
    r = pow(alpha, k, p)
 
    # Step 4: Compute s
    k_inv = mod_inverse(k, p - 1)
    s = (k_inv * (m - private_key * r)) % (p - 1)
 
    # Edge case: s should not be 0
    if s == 0:
        return sign_vault(vault_content, private_key, p, alpha)  # retry
 
    return (r, s)
 
 
def verify_vault(vault_content: str, signature: tuple, public_key: int, p: int, alpha: int) -> bool:
    """
    Verify the ElGamal signature of the vault content.
 
    Args:
        vault_content : the encrypted vault string (from vault.json "encrypted_vault")
        signature     : (r, s) tuple stored in vault.json
        public_key    : ElGamal public key y (from Module 1)
        p             : large prime from config
        alpha         : primitive root modulo p from config
 
    Returns:
        True if signature is valid, False if tampered
 
    ElGamal Verification:
        m = SHA-256(vault_content) as integer
        left  = alpha^m mod p
        right = (public_key^r * r^s) mod p
        valid if left == right
    """
    r, s = signature
 
    # Basic sanity checks on signature values
    if not (0 < r < p):
        return False
    if not (0 < s < p - 1):
        return False
 
    # Step 1: Hash the vault content (must match exactly what was signed)
    m = hash_vault_content(vault_content)
 
    # Step 2: Compute both sides of the verification equation
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
 
    print("[✓] Vault signed successfully.")
 
 
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
 
    print("[✓] Vault signature verified. Safe to open.")
    return vault_data