import json
import os
import hashlib
from Crypto.Cipher import AES

def construct_key(master_password: str) -> bytes:
    # The user would input a varying length password, we use hash to get a fixed length key for AES
    return hashlib.sha256(master_password.encode("utf-8")).digest()

def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM) #did not specify nonce parameters so that it gets to be random each time
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce + ciphertext + tag


def aes_gcm_decrypt(key: bytes, blob: bytes) -> bytes:
    nonce = blob[:16]
    tag = blob[-16:] #last 16 bytes are the authentication tag reserved by how AES GCM works
    ciphertext = blob[16:-16]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext


def _read_vault_file(vault_path: str) -> dict:
    with open(vault_path) as f:
        return json.load(f)


def _write_vault_file(vault_path: str, data: dict):
    with open(vault_path, "w") as f:
        json.dump(data, f, indent=2)


def _decrypt_credentials(vault_path: str, key: bytes) -> list:
    vault = _read_vault_file(vault_path)
    blob = bytes.fromhex(vault["encrypted_vault"])
    plaintext = aes_gcm_decrypt(key, blob)
    return json.loads(plaintext.decode("utf-8"))


def _encrypt_and_save(vault_path: str, credentials: list, key: bytes) -> str:
    plaintext = json.dumps(credentials, indent=2).encode("utf-8")
    blob = aes_gcm_encrypt(key, plaintext)
    blob_hex = blob.hex()
    vault = _read_vault_file(vault_path) if os.path.exists(vault_path) else {}
    vault["encrypted_vault"] = blob_hex
    vault["signature"] = None   
    _write_vault_file(vault_path, vault)
    return blob_hex

#master password is used to derive the same AES key each time 

def create_vault(vault_path: str, master_password: str) -> str:
    key =construct_key(master_password)
    return _encrypt_and_save(vault_path, [], key)


def add_credential(vault_path: str, master_password: str,
                   website: str, username: str, password: str) -> str:
    key =construct_key(master_password)
    credentials = _decrypt_credentials(vault_path, key)
    for c in credentials:
        if c["website"] == website and c["username"] == username:
            print(f"[Vault] Entry for {website}/{username} already exists. Use 'update'.")
            return None
    credentials.append({"website": website, "username": username, "password": password})
    blob_hex = _encrypt_and_save(vault_path, credentials, key)
    print(f"[Vault] Added credential for '{website}' / '{username}'")
    return blob_hex


def retrieve_credential(vault_path: str, master_password: str, website: str) -> list:
    key =construct_key(master_password)
    credentials = _decrypt_credentials(vault_path, key)
    matches = [c for c in credentials if c["website"] == website]
    return matches


def list_credentials(vault_path: str, master_password: str) -> list:
    key =construct_key(master_password)
    return _decrypt_credentials(vault_path, key)


def update_credential(vault_path: str, master_password: str,
                      website: str, username: str, new_password: str) -> str:
    key =construct_key(master_password)
    credentials = _decrypt_credentials(vault_path, key)
    updated = False
    for c in credentials:
        if c["website"] == website and c["username"] == username:
            c["password"] = new_password
            updated = True
            break
    if not updated:
        print(f"[Vault] Entry not found for '{website}' / '{username}'")
        return None
    blob_hex = _encrypt_and_save(vault_path, credentials, key)
    print(f"[Vault] Updated credential for '{website}' / '{username}'")
    return blob_hex


def delete_credential(vault_path: str, master_password: str,
                      website: str, username: str) -> str:
    key =construct_key(master_password)
    credentials = _decrypt_credentials(vault_path, key)
    original_len = len(credentials)
    credentials = [c for c in credentials
                   if not (c["website"] == website and c["username"] == username)]
    if len(credentials) == original_len:
        print(f"[Vault] Entry not found for '{website}' / '{username}'")
        return None
    blob_hex = _encrypt_and_save(vault_path, credentials, key)
    print(f"[Vault] Deleted credential for '{website}' / '{username}'")
    return blob_hex


def get_encrypted_blob_hex(vault_path: str) -> str:
    #would be for signing
    vault = _read_vault_file(vault_path)
    return vault["encrypted_vault"] 