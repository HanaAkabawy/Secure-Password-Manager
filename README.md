# Secure Password Manager

A cryptographic password manager built from scratch for CMPS426 — Security of Computer Systems and Networks. All cryptographic primitives (ElGamal key generation, digital signatures, Diffie-Hellman key exchange, Miller-Rabin primality testing) are implemented without external crypto libraries.

---

## Features

- **AES-256-GCM** encrypted vault for storing credentials
- **ElGamal digital signatures** to detect vault tampering
- **Diffie-Hellman key exchange** for secure vault transfer between users
- **Safe prime generation** using Miller-Rabin primality testing
- CLI interface and optional Flask web UI
- Multi-user support with isolated per-user vaults

---

## Project Structure

```
Secure-Password-Manager/
├── pwm/
│   ├── elgamal.py       # Module 1: ElGamal key generation
│   ├── vault.py         # Module 2: AES-GCM vault encryption & credential CRUD
│   ├── signatures.py    # Module 3: ElGamal digital signatures
│   ├── dh_export.py     # Module 4: Diffie-Hellman vault export
│   └── dh_params.json   # Shared DH parameters
├── main.py              # CLI entry point
├── app.py               # Flask web UI
├── tests/               # Integration tests
├── ctf/                 # CTF challenge solutions (ctf1–ctf6)
├── users/               # Per-user vault storage (auto-created)
└── docs/                # Design documents and project spec
```

---

## Requirements

```
pip install pycryptodome flask
```

Python 3.10+ required.

---

## Usage

### CLI

```bash
python main.py
```

On first run you will see:

```
  --- Password Manager ---

  1) Initialize new user
  2) Login
  3) Exit

  Choose an option:
```

**Initialize a new user** creates an encrypted vault protected by a master password.  
**Login** unlocks an existing vault and opens the vault menu:

```
  1) Add credential
  2) Get credential
  3) List all sites
  4) Update credential
  5) Delete credential
  6) Export vault to another user
  7) Import vault from a user
  8) Logout
```

### Web UI

```bash
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

---

## Cryptographic Modules

### Module 1 — Key Management (`pwm/elgamal.py`)

Generates long-lived ElGamal public/private key pairs used for signing.

- Safe prime generation (`p` where `2p+1` is also prime)
- 40-round Miller-Rabin primality test
- Keys stored as JSON in `users/<name>/elgamal_pub.json` and `elgamal_priv.json`

### Module 2 — Vault Encryption (`pwm/vault.py`)

Stores credentials encrypted with AES-256-GCM.

- Master password → 32-byte AES key via SHA-256
- Random nonce per encryption; authentication tag detects bit-level tampering
- Full CRUD: add, retrieve, list, update, delete

### Module 3 — Digital Signatures (`pwm/signatures.py`)

Signs the encrypted vault blob using ElGamal signatures.

- Signature is over encrypted content, not plaintext
- Verification runs on every vault open — any modification raises `PermissionError`
- Signature `(r, s)` stored alongside the vault in `vault.json`

### Module 4 — Secure Vault Export (`pwm/dh_export.py`)

Transfers a vault between devices using an authenticated Diffie-Hellman key exchange.

**Three-phase protocol:**

1. **Key Exchange** — both sides generate ephemeral DH keypairs, sign their public keys with ElGamal, and verify each other's signatures before deriving a shared session key.
2. **Export** — sender decrypts vault with master password, re-encrypts with session key, signs the package.
3. **Import** — receiver verifies signature, decrypts with session key, re-encrypts under their own master password.

This provides **forward secrecy**: compromising the long-lived ElGamal key does not expose past session keys.

---

## Vault Export Workflow

**On the sender's machine:**

```
Choose option 6 (Export vault to another user)
Enter recipient username: bob
```

This generates `users/<you>/dh_offer.json` and, once Bob's offer is also present, produces `users/<you>/vault_export.json`.

**On the recipient's machine:**

```
Choose option 7 (Import vault from a user)
Enter sender username: alice
```

Bob must have previously run Export to generate his own DH offer. Both offer files must be accessible (e.g., on a shared filesystem or copied manually).

---

## Running Tests

```bash
python -m pytest tests/
```

| Test file | What it covers |
|---|---|
| `test_dh_roundtrip.py` | Both parties derive the same shared secret |
| `test_export_package.py` | Full export → import → credential recovery |
| `test_import_tamper.py` | Tampered export package raises an error |
| `test_cli_e2e.py` | End-to-end CLI vault operations |

---

## CTF Challenges

Six standalone challenge scripts are in `ctf/`:

```bash
python ctf/ctf1.py
python ctf/ctf2.py
# ...
```

Each script is self-contained and reads from `ctf/CTF_DATA/`.

---

## Security Notes

- Private keys are stored as **plaintext JSON** — this is intentional for the scope of this academic project.
- The master password is used as `SHA-256(password)` directly. A production system would use a proper KDF (Argon2, PBKDF2).
- DH parameters default to 512-bit for fast testing. Set a higher bit size for stronger security.
