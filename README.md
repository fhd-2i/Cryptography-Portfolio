# Cryptography Portfolio

A collection of practical applied cryptography projects focused on secure system design, encryption, key management, authentication, integrity, digital signatures, and modern cryptographic primitives.

The portfolio demonstrates the practical integration of classical, post-quantum, and software supply chain cryptography using Python.

---

## Projects

### 01 - Cryptographic Secure File Vault

A hybrid cryptographic file protection system designed to provide confidentiality, integrity, authenticity, and secure key management.

**Cryptographic technologies:**

- AES-256-GCM for authenticated file encryption
- X25519 ECDH for key agreement
- HKDF-SHA256 for key derivation
- AES-256-GCM for file-key wrapping
- Ed25519 digital signatures
- SHA-256 integrity verification
- Scrypt-based private-key protection
- Trusted signing-key verification
- Command-line and graphical interfaces
- 48 automated cryptographic and security tests

**Project:** [01-Cryptographic-Secure-File-Vault](./01-Cryptographic-Secure-File-Vault/)

---

### 02 - Post-Quantum Hybrid Key Exchange

A hybrid cryptographic key-establishment prototype combining classical and post-quantum cryptography for secure session-key derivation.

**Cryptographic technologies:**

- X25519 classical key agreement
- ML-KEM-768 post-quantum key encapsulation
- Hybrid classical + post-quantum secret combination
- HKDF-SHA256 session-key derivation
- AES-256-GCM authenticated encryption
- Structured encrypted message packages
- Persistent recipient cryptographic identity
- Command-line interface
- Automated cryptographic and tamper-detection tests

This project explores a hybrid migration approach in which independent classical and post-quantum secret material is combined before deriving the final symmetric session key.

**Project:** [02-Post-Quantum-Hybrid-Key-Exchange](./02-Post-Quantum-Hybrid-Key-Exchange/)

---

### 03 - Software Supply Chain Artifact Signer

A cryptographic software artifact signing and verification tool designed to detect unauthorized modifications to individual files and complete software releases.

**Cryptographic technologies and features:**

- SHA-256 artifact fingerprinting
- Ed25519 digital signatures
- Individual file signing and verification
- Signed software release manifests
- Release-directory integrity verification
- Modified artifact detection
- Missing artifact detection
- Unexpected artifact detection
- Manifest tamper detection
- Signature inspection
- Interactive command-line interface
- Built-in cryptographic help and explanations

For software releases, the tool creates a manifest containing the SHA-256 fingerprint of each artifact and digitally signs the manifest using Ed25519. Verification first authenticates the manifest and then compares the current artifacts against the signed metadata.

**Project:** [03-Software-Supply-Chain-Artifact-Signer](./03-Software-Supply-Chain-Artifact-Signer/)

---

## Cryptographic Areas Covered

Across the portfolio, the projects demonstrate practical experience with:

- Symmetric authenticated encryption
- Elliptic-curve key agreement
- Key derivation functions
- Digital signatures
- Cryptographic hashing
- Password-based key protection
- Envelope encryption
- Post-quantum cryptography
- Hybrid classical/post-quantum key establishment
- Software supply chain integrity
- Cryptographic key management
- Tamper detection and verification

---

## Technology

- Python
- `cryptography`
- ML-KEM
- Pytest

---

## Disclaimer

These projects are educational and research-oriented implementations developed to demonstrate applied cryptographic engineering concepts. They are not intended to replace audited production cryptographic systems.