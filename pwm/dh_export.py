import json
import secrets
import hashlib
from pwm.vault import aes_gcm_encrypt, aes_gcm_decrypt, _decrypt_credentials, _encrypt_and_save
from pwm._mock_elgamal import sign, verify

def is_prime(n, k=40):
    if n == 2 or n == 3: return True
    if n < 2 or n % 2 == 0: return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_dh_params(bits: int = 2048) -> tuple[int, int]:
    while True:
        p = secrets.randbits(bits - 1)
        p |= (1 << (bits - 2)) | 1
        q = 2 * p + 1
        if q.bit_length() == bits and is_prime(p) and is_prime(q):
            alpha = 2
            while True:
                if pow(alpha, 2, q) != 1 and pow(alpha, p, q) != 1:
                    return q, alpha
                alpha += 1

def load_dh_params(path: str = "pwm/dh_params.json") -> tuple[int, int]:
    with open(path, "r") as f:
        data = json.load(f)
    return int(data["q"], 16), int(data["alpha"])

def save_dh_params(q: int, alpha: int, path: str = "pwm/dh_params.json"):
    with open(path, "w") as f:
        json.dump({"q": hex(q), "alpha": str(alpha)}, f, indent=2)

def generate_dh_keypair(q: int, alpha: int) -> tuple[int, int]:
    a = secrets.randbelow(q - 2) + 2
    A = pow(alpha, a, q)
    return a, A

def compute_shared_secret(other_public: int, my_private: int, q: int) -> int:
    return pow(other_public, my_private, q)

def derive_session_key(shared_secret: int) -> bytes:
    byte_length = (shared_secret.bit_length() + 7) // 8
    secret_bytes = shared_secret.to_bytes(byte_length, byteorder='big')
    return hashlib.sha256(secret_bytes).digest()

def sign_dh_public(dh_public: int, elgamal_priv) -> bytes:
    byte_length = (dh_public.bit_length() + 7) // 8
    msg_bytes = dh_public.to_bytes(byte_length, byteorder='big')
    return sign(msg_bytes, elgamal_priv)

def verify_dh_public(dh_public: int, signature: bytes, elgamal_pub) -> bool:
    byte_length = (dh_public.bit_length() + 7) // 8
    msg_bytes = dh_public.to_bytes(byte_length, byteorder='big')
    return verify(msg_bytes, signature, elgamal_pub)

class SignatureVerificationError(Exception):
    pass

def build_export_package(
    vault_path: str,
    master_password: str,
    my_dh_priv: int,
    my_dh_pub: int,
    peer_dh_pub: int,
    my_elgamal_priv,
    my_elgamal_pub,
    q: int,
    alpha: int,
) -> dict:
    from pwm.vault import construct_key
    master_key = construct_key(master_password)
    entries = _decrypt_credentials(vault_path, master_key)
    
    entries_bytes = json.dumps(entries).encode("utf-8")
    
    shared_secret = compute_shared_secret(peer_dh_pub, my_dh_priv, q)
    session_key = derive_session_key(shared_secret)
    
    session_blob = aes_gcm_encrypt(session_key, entries_bytes)
    
    session_nonce = session_blob[:16]
    session_tag = session_blob[-16:]
    session_ciphertext = session_blob[16:-16]
    
    signature = sign(session_ciphertext, my_elgamal_priv)
    
    return {
        "sender_dh_pub": hex(my_dh_pub),
        "sender_elgamal_pub_fingerprint": str(my_elgamal_pub),
        "session_ciphertext_hex": session_ciphertext.hex(),
        "session_nonce_hex": session_nonce.hex(),
        "session_tag_hex": session_tag.hex(),
        "signature_hex": signature.hex()
    }

def consume_export_package(
    package: dict,
    my_dh_priv: int,
    peer_elgamal_pub,
    new_master_password: str,
    output_vault_path: str,
    my_elgamal_priv,
    q: int,
) -> None:
    from pwm.vault import construct_key
    
    session_ciphertext = bytes.fromhex(package["session_ciphertext_hex"])
    session_nonce = bytes.fromhex(package["session_nonce_hex"])
    session_tag = bytes.fromhex(package["session_tag_hex"])
    signature = bytes.fromhex(package["signature_hex"])
    
    if not verify(session_ciphertext, signature, peer_elgamal_pub):
        raise SignatureVerificationError("Export package signature is invalid or tampered!")
        
    peer_dh_pub = int(package["sender_dh_pub"], 16)
    shared_secret = compute_shared_secret(peer_dh_pub, my_dh_priv, q)
    session_key = derive_session_key(shared_secret)
    
    session_blob = session_nonce + session_ciphertext + session_tag
    entries_bytes = aes_gcm_decrypt(session_key, session_blob)
    entries = json.loads(entries_bytes.decode("utf-8"))
    
    master_key = construct_key(new_master_password)
    _encrypt_and_save(output_vault_path, entries, master_key)

