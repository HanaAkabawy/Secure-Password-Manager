# Secure Password Manager - Design Decisions

## Module 4: Diffie-Hellman Key Exchange & Secure Export

### Cryptographic Workflow
To securely transfer a password vault from Device 1 to Device 2, we implement a **Signed Diffie-Hellman Key Exchange** combined with **AES-GCM Authenticated Encryption**.

1. **Forward Secrecy via Ephemeral DH Keys:**
   Instead of encrypting the vault payload directly with a long-lived key (such as ElGamal), we generate a fresh, ephemeral Diffie-Hellman keypair for every single export session. Once the export is complete, the DH private keys can be discarded. This ensures **Forward Secrecy**: even if a user's long-lived ElGamal private key is compromised in the future, past exported vaults cannot be decrypted, because the DH session key was destroyed.

2. **Mitigating Man-In-The-Middle (MITM) via ElGamal Signatures:**
   Diffie-Hellman alone is vulnerable to MITM attacks. To prevent this, each device cryptographically signs its ephemeral DH public key using its long-lived ElGamal private key (from Module 1/3) before sending it to the other party. The peer verifies the signature before using the DH public key to compute the shared secret. Without the valid signature, the exchange aborts.

3. **Transit Integrity for the Encrypted Payload:**
   After the shared secret is established, the sender derives a 32-byte session key using SHA-256 and encrypts the vault entries using AES-GCM. AES-GCM provides both confidentiality and authenticity against tampering by an external attacker. Additionally, the sender signs the resulting ciphertext (using ElGamal) to provide **non-repudiation**—the receiver can mathematically prove the vault came exclusively from the expected sender and was not replaced in transit.

4. **Choice of Parameters:**
   We enforce a prime modulus size of **2048 bits** for the Diffie-Hellman parameters ($q$). This provides adequate security against discrete logarithm attacks and aligns with the size of the SHA-256 digest we use for deriving the 256-bit AES session key. The parameters are generated using Miller-Rabin primality testing to ensure $q$ is a safe prime, maximizing the cryptographic strength of the group.

---

## CTF 4: LSB Steganography

**Observation:**
The challenge provided a `.png` file (`stego.png`) with no obvious visual distortions, suggesting hidden data within the image channels.

**Hypothesis:**
The data is embedded using Least Significant Bit (LSB) Steganography, where the lowest bits of the color channels represent the ASCII bits of the hidden message.

**Methodology & Tools:**
Using Python and the `Pillow` library:
- I extracted the pixel data of the image.
- By isolating the 0th bit (`& 1`) of the Red channel (`R`) and reading the bits from most-significant to least-significant (`msb`), the bits were collected into a stream.
- Re-assembling every 8 bits back into a byte and decoding them into ASCII revealed the hidden string.

**Result:**
The extraction code successfully revealed the flag by looking at just the Red channel with MSB bit ordering. 
**Flag:** `CMPN{Hidd3n_in_pl4in_sigh7}`