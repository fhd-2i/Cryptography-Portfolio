\# Cryptographic Secure File Vault



A practical cryptographic file protection system built with Python and the `cryptography` library.



The project implements authenticated file encryption, secure key management, elliptic-curve key agreement, key derivation, digital signatures, and file integrity verification.



\---



\## Overview



Cryptographic Secure File Vault is a secure file encryption application designed to demonstrate practical applied cryptography rather than simple password-based file encryption.



The system uses a hybrid cryptographic architecture:



\- AES-256-GCM for file encryption

\- X25519 ECDH for key agreement

\- HKDF-SHA256 for key derivation

\- AES-256-GCM for protecting the per-file encryption key

\- Ed25519 for digital signatures

\- SHA-256 for plaintext integrity verification

\- Scrypt for password-based protection of private keys



The application provides both:



\- Command-line interface (CLI)

\- Graphical user interface (GUI)



\---



\## Cryptographic Architecture



The system uses envelope encryption.



Each encrypted file receives a new random 256-bit File Encryption Key (FEK).



The FEK is then protected using a Key Encryption Key (KEK) derived from X25519 ECDH and HKDF-SHA256.



\### Cryptographic components



| Component | Algorithm | Purpose |

|---|---|---|

| File encryption | AES-256-GCM | Confidentiality and authenticated encryption |

| Key exchange | X25519 ECDH | Establish shared secret |

| Key derivation | HKDF-SHA256 | Derive the KEK |

| FEK protection | AES-256-GCM | Protect the file encryption key |

| Digital signature | Ed25519 | Authenticity and tamper detection |

| File fingerprint | SHA-256 | Integrity verification |

| Private-key protection | Scrypt + AES-256-GCM | Protect private keys at rest |



\---



\## Encryption Workflow



The encryption process follows these steps:



1\. Read the plaintext file.

2\. Generate a cryptographically secure random 256-bit FEK.

3\. Generate a random AES-GCM nonce.

4\. Encrypt the plaintext using AES-256-GCM.

5\. Generate a temporary X25519 ephemeral key pair.

6\. Perform X25519 ECDH using:

&#x20;  - Ephemeral private key

&#x20;  - Recipient public key

7\. Generate a random 128-bit salt.

8\. Derive a 256-bit KEK using HKDF-SHA256.

9\. Encrypt/wrap the FEK using AES-256-GCM.

10\. Calculate the SHA-256 hash of the original plaintext.

11\. Build the vault package.

12\. Sign the canonical vault metadata using Ed25519.

13\. Store the encrypted vault as a JSON-based `.vault` file.



\---



\## Decryption Workflow



The decryption process performs verification before releasing the plaintext:



1\. Read the `.vault` file.

2\. Parse and validate the vault structure.

3\. Validate cryptographic parameters and field sizes.

4\. Load the trusted local Ed25519 public key.

5\. Compare the vault's embedded signing public key with the trusted local key.

6\. Reject the vault if the signing key is not trusted.

7\. Verify the Ed25519 digital signature.

8\. Reject modified or tampered vaults.

9\. Load the protected X25519 private key.

10\. Perform X25519 ECDH using the recipient private key and vault ephemeral public key.

11\. Derive the KEK using HKDF-SHA256.

12\. Recover the FEK using AES-256-GCM.

13\. Decrypt the encrypted file using AES-256-GCM.

14\. Calculate the SHA-256 hash of the restored plaintext.

15\. Compare the calculated hash with the stored hash.

16\. Write the restored file only after successful verification.



\---



\## Security Model



The project follows a layered cryptographic design.



\### Confidentiality



AES-256-GCM encrypts the actual file contents.



A unique random FEK is generated for every file.



The FEK is never stored directly in plaintext inside the vault.



\### Key Agreement



X25519 ECDH is used to establish a shared secret between the ephemeral encryption key and the recipient identity.



\### Key Derivation



HKDF-SHA256 derives a 256-bit KEK from the X25519 shared secret and a random salt.



\### Key Protection



Private X25519 and Ed25519 keys are encrypted at rest.



The password is processed using Scrypt and the resulting key is used with AES-256-GCM to protect the private key material.



\### Authenticity



Ed25519 signatures protect the vault package from unauthorized modification.



The system does not blindly trust the public key stored inside the vault.



The embedded Ed25519 public key must match the locally trusted public key before the signature is accepted.



\### Integrity



AES-GCM provides authenticated encryption.



Additionally, SHA-256 is used as an independent plaintext fingerprint verification mechanism.



\---



\## Vault Format



The encrypted file is stored as a JSON object.



The vault contains fields including:



\- Version

\- Encryption algorithm

\- Key exchange algorithm

\- KDF

\- Salt

\- Ephemeral X25519 public key

\- File encryption nonce

\- Wrapped-key nonce

\- Wrapped FEK

\- Ed25519 signing public key

\- Digital signature

\- Ciphertext

\- SHA-256 file hash

\- Original filename



Binary values are encoded using Base64.



The signature is generated over a canonical representation of the vault package with the signature field excluded.



\---



\## Project Structure



```text

cryptographic-secure-vault/

│

├── app/

│   ├── aes.py

│   ├── ecc.py

│   ├── hashing.py

│   ├── identity.py

│   ├── key\_management.py

│   ├── main.py

│   ├── signatures.py

│   ├── vault\_engine.py

│   ├── vault\_format.py

│   └── \_\_init\_\_.py

│

├── gui/

│   ├── app.py

│   └── \_\_init\_\_.py

│

├── tests/

│   ├── test\_aes.py

│   ├── test\_key\_exchange.py

│   ├── test\_key\_management.py

│   ├── test\_signatures.py

│   └── test\_vault.py

│

├── keys/

│   ├── ed25519\_private.key

│   ├── ed25519\_public.key

│   ├── x25519\_private.key

│   └── x25519\_public.key

│

├── requirements.txt

├── README.md

├── .gitignore

└── secret.txt

