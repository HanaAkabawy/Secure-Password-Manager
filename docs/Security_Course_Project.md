

# 

# **Security Course Project**

Secure Password Manager \+ Capture The Flags

| Component | Description |
| :---- | :---- |
| Part 1 | Secure Password Manager (4 Modules) |
| Part 2 | 6 CTF Challenges |

# **Part 1: Secure Password Manager**

## **Description**

Password managers are one of the most practical applications of cryptography in everyday life. They allow users to securely store, retrieve, and manage credentials using strong encryption, so that a single master password protects hundreds of accounts.

In this project, you will build a **Secure Password Manager** — a command-line application that uses AES for encryption, SHA for hashing, ElGamal Digital Signatures for integrity verification, and Diffie-Hellman for secure vault (a **secure encrypted storage**) export between users.

You need to implement Diffie-Hellman, ElGamal Digital Signatures, and the overall system logic from scratch. **You may import ready-made implementations for AES (used internally for vault encryption) and SHA hash functions.**

## **System Overview**

**Local workflow:** A user sets up a vault with a master password, stores credentials, and retrieves them. Every vault operation is integrity-checked with digital signatures.

**Export workflow:** A user exports their vault to another user/device using Diffie-Hellman key exchange, with digital signatures protecting against man-in-the-middle attacks.

## 

## 

## 

## 

## 

## 

## 

## 

## 

## 

## **Module 1: ElGamal Key Management**

### **Inputs:**

-  User identity (username)

### **Outputs:**

-   ElGamal public/private key pair

-   Exported public key file (for sharing)

### **Functionality:**

When a user initializes their password manager for the first time, this module generates EL Gamal key pair (for digital signatures in Modules 3 and 4):

* Read shared parameters (large prime p and primitive root α) from a configuration file, or generate them per user.   
* Generate an ElGamal key pair using these parameters.

### **Properties:**

1. ElGamal must be implemented from scratch.

2. **Key storage:**  
-  The private key is saved locally and protected.  
-  The Public key is exportable for sharing with other users.  
-  The ElGamal public key allows others to verify this user's signatures.

3. **Private keys must never be exposed or transmitted**

4. The key pair is  generated once during user initialization and reused across all modules.

## **Module 2: Vault Encryption & Credential Management**

### **Inputs:**

* Master password

  * Credential operations (add / retrieve / update / delete)

### **Outputs:**

* Encrypted vault file

  * Decrypted credentials on retrieval (the vault is decrypted in memory and the selected entry is displayed to the user)

### **Functionality:**

During vault initialization, the **SHA-256** of the master password is used as the AES **data key.** This data key is used to encrypt and decrypt the entire vault file.

**On adding:**

* The user provides the master password.  
* The entire vault is decrypted using the **data key**.   
* The new credential (website, username, password) is added.   
* The entire vault is re-encrypted using the data key.   
* The vault is then re-signed (see Module 3).

**On retrieval:**

* The user provides the master password.  
* The entire vault is decrypted in memory using the **data key**.  
*  The selected entry is displayed to the user.

     **On update/delete:** 

* The user provides the master password.   
* The entire vault is decrypted using the data key.   
* The selected entry is modified/deleted.  
*  The entire vault is re-encrypted using the data key.  
*  The vault is then re-signed.

This approach uses symmetric encryption for both security and efficiency, allowing encryption of arbitrary-length data while ensuring that only a user with the correct master password can access the vault contents.

The vault is stored as a **JSON file**. The JSON structure contains:

* The AES-encrypted credential entries  
* The digital signature over the vault contents (see Module 3).

JSON file example:

![][image1]

### **Properties:**

1. Adding, retrieving, updating, and deleting credentials should work correctly.

2. The vault file should be unusable without the correct master password.

3. You are free to import a ready-made implementation for AES and SHA-256.

4. Note: you should use AES\_GCM Mode   **AES.new(key, AES.MODE\_GCM)**

 


## **Module 3: Digital Signatures for Vault Integrity**

### **Inputs:**

* Vault file to sign or verify

  * User's ElGamal private key from Module 1 (for signing) or ElGamal public key from Module 1(for verification)

### **Outputs:**

* Signed vault file

  * Verification result (valid / invalid \+ alert)

### **Functionality**

Every time the vault is modified (credential added, updated, or deleted), the vault is re-signed using the user's private key with an **ElGamal digital** **signature.**

Every time the vault is opened, the signature is verified before any credentials are shown. If the signature is invalid (i.e., someone tampered with the vault file), the user is alerted and the vault refuses to open.

1. #### **Signing process:**

   1. Compute a SHA-256 hash of the vault contents (encrypted content).

   2. Sign the hash using the user's private key (ElGamal signature)

   3. Store the signature alongside the vault. 

2. #### **Verification process:**

   1. Compute the SHA-256 hash of the current vault contents (encrypted content)

   2. Verify the stored signature against the hash using the user's ElGamal public key.

   3. If verification fails, refuse to open and warn the user.

### **Properties:**

1. The digital signature scheme must be implemented from scratch.

2. You are free to import a ready-made function for **SHA-256.**

3. Any manual edit to the vault file (even a single bit flip) must cause verification to fail.

4. This module does not generate any keys — it relies entirely on the ElGamal key pair generated by Module 1\.

## **Module 4: Secure Vault Export via Diffie-Hellman**

### **Inputs:**

* Device 1’s  vault 

  * Device 1’s ELGamal private key

  * Device 2’s  ELGamal public key

  * Device 1’s ElGamal public key (shared with recipient for signature verification)

  * Shared Diffie-Hellman (DH) parameters (q, α from a public config file)

### **Outputs:**

* Encrypted and signed vault export package

  * Successfully imported vault on recipient's side

### **Functionality:**

This module enables a user to securely export their vault to another device.

### **Key Exchange Phase**

1. Both devices read the shared Diffie-Hellman parameters (q,α), where q is a large prime and α is a primitive root modulo q.  
2. Each device generates a Diffie-Hellman key pair: a private key and a public key.  
3. Device 1 sends its DH public key, signed with its digital signature.  
4. Device 2 verifies the signature; if invalid, the process is aborted.  
5. Device 2 sends its DH public key, also signed.  
6. Device 1 verifies the signature; if invalid, the process is aborted.  
7. Both devices compute the shared secret.  
8. A session AES-256 key is derived from the shared secret using SHA-256.

### **Transfer Phase**

1. On Device 1, the user enters the master password.  
2. The AES key (data key) is used to **decrypt all vault entries locally.**  
3. The decrypted vault data (in memory only) is then **encrypted with the session key derived from Diffie-Hellman.**  
4. A new ElGamal digital signature is computed over the session-key-encrypted data using Device 1's private key.  
5. The encrypted data along with the new signature is transmitted to Device 2\.  
6. Device 2 verifies the new signature using Device 1's ElGamal public key to ensure the data has not been tampered with in transit.   
7. If verification fails, the import is aborted.

### **Import Phase**

1. Device 2 derives the same session key from the shared secret.  
2. The received encrypted vault data is decrypted using this session key.  
3. The user enters their master password (same or new).  
4. A new AES key (data key) is derived from the master password, and **the vault is re-encrypted and stored locally.**  
5. A new ElGamal digital signature is computed over the newly encrypted vault using Device 2's private key, replacing Device 1's signature.

### **Properties:**

1. Diffie-Hellman must be implemented from scratch.  
2. If either signature verification fails, the export must abort.  
3. You are free to import a ready-made implementation for AES and SHA-256.  
4. DH keys are ephemeral (generated per export session), while signature keys are long-lived

## **Bonus:**

* Implementing a UI instead of a CLI will be considered a bonus within the project’s total grade and will not be propagated to any other classwork grades.

## **Part 1 Deliverables:**

1. A program implementing all 4 modules with a working CLI interface.

2. Should demonstrate the full workflow: setup → store credentials → sign → verify →export to another user → import.

3. README file explaining how to run your application.

4. Documentation covering your design decisions, algorithm choices, and any challenges faced.

# **Part 2: CTFs (Capture The Flags)**

In this part you will solve 9 CTF tasks. You can find the challenge files attached with this document.

Each task will ask you to find a hidden flag in a different way and your job is to find this flag correctly. You may deal with text files, images, audio, network captures, log files, or binary data.

The flag structure can be one of:

1. CMPN{some\_text}

2. FLAG{some\_text}

3. SOME\_TEXT

### 

### **CTF 1 — Packet Analysis**

You have been given a network capture file traffic.pcapng. A secret flag was transmitted during a suspicious TCP session.

The flag has been split across multiple TCP packets and base64-encoded before transmission. Reassemble the data from the TCP stream and decode it to find the original flag.

*Hint: Filter for TCP traffic on port 4444\. Extract the payload data from each packet in order and concatenate before decoding.*

### **CTF 2 — Image Manipulation**

You have two PNG images: layer1.png and layer2.png. Each image appears to be random noise on its own, but together they reveal a secret.

### **CTF 3 — Bit Shifting**

You are given a text file shifted.txt containing a sequence of decimal numbers. Each number represents a character that has been bit-shifted. Find the right operation to recover the original ASCII characters and reveal the flag.

### **CTF 4 — Steganography**

Steganography is the practice of hiding data inside another file. You are given an image file innocent.png that looks like an ordinary photograph. Something is HIDING inside this image using LSB (Least Significant Bit) steganography.

### 

### **CTF 5 — CBC Padding Oracle**

You are testing a website that is encrypting a secret. However, the website is designed badly and leaks whether after decryption the padding of clear text is right or gives an error. Can you use this piece of information to leak the secret without knowing the key?

[http://cbc-ctf.westeurope.azurecontainer.io:5000/](http://cbc-ctf.westeurope.azurecontainer.io:5000/)

### **CTF 6 — RSA Key Recovery**

You intercepted an encrypted message along with the RSA public key used to encrypt it. However, the key was generated poorly — the primes used are too close together.

##### **Public Key:**

**Ciphertext (decimal):**

## **CTF Deliverables:**

* Submit a single **zip file** containing:

  * A **PDF document** containing your CTF solutions for Part 2

  * Any code files used to solve CTF challenges

## 

## **Rules**

1. Group size is up to **4 members**.  
2. The deadline is **Week 13**  
3. The project should be implemented in **Python**.  
4. Diffie-Hellman, and ElGamal Digital Signatures must be implemented **from scratch**. Using external cryptography libraries for these algorithms will result in a **zero grade** for the affected module. You may only import ready-made implementations for AES and SHA hash functions as stated in the project description.  
5. **AI-generated/copied code is strictly prohibited.** Any submission found to contain code generated by AI tools will receive a **zero grade for the entire project**.  
6. **Copying from colleagues is plagiarism.** Submissions will be checked for similarity against each other. Teams found to have shared or copied code will **all receive a zero grade**. This applies to both the team that copied and the team that provided the code.  
7. **CTF solutions without explanation will be discarded.** For each CTF, you must document your thought process, the steps you followed, the tools you used, and how you arrived at the flag.   
8. Any code used to solve CTF problems must be included in the submission.

[image1]: <data:image/png;base64,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>