\# Software Supply Chain Artifact Signer



A Python-based cryptographic tool for signing and verifying software artifacts and release directories.



The project demonstrates how cryptographic hashing and digital signatures can be used to detect unauthorized changes to software artifacts throughout the software supply chain.



\## Features



\- Interactive command-line interface

\- SHA-256 artifact hashing

\- Ed25519 digital signatures

\- Single-file signing and verification

\- Complete software release directory signing

\- Signed release manifests

\- Detection of modified files

\- Detection of missing files

\- Detection of unexpected files

\- Manifest tamper detection

\- Signature inspection

\- Built-in help menu



\## Cryptographic Design



The tool uses two primary cryptographic mechanisms:



\### SHA-256



SHA-256 is used to calculate a cryptographic fingerprint for software artifacts.



For release directories, the tool calculates the SHA-256 hash and size of every artifact and stores the results inside a release manifest.



If an artifact changes after the release is signed, its newly calculated hash will no longer match the signed manifest.



\### Ed25519



Ed25519 digital signatures provide authenticity and integrity protection.



For individual files, the artifact itself is digitally signed.



For software releases, the generated manifest is signed using the Ed25519 private key.



Verification is performed using the trusted Ed25519 public key.



\## Release Signing Architecture



```text

Software Release

&#x20;     |

&#x20;     v

Scan Artifacts

&#x20;     |

&#x20;     v

SHA-256 Hashes

&#x20;     |

&#x20;     v

Release Manifest

&#x20;     |

&#x20;     v

Ed25519 Signature

&#x20;     |

&#x20;     v

Signed Release Metadata

```



During verification:



```text

Trusted Public Key

&#x20;      |

&#x20;      v

Verify Manifest Signature

&#x20;      |

&#x20;      v

Recalculate Artifact Hashes

&#x20;      |

&#x20;      v

Compare With Signed Manifest

&#x20;      |

&#x20;      +--> Unchanged

&#x20;      +--> Modified

&#x20;      +--> Missing

&#x20;      +--> Unexpected

```



\## Interactive Interface



Start the tool with:



```bash

python -m app.main

```



The interactive menu provides:



```text

\[1] Generate Signing Identity

\[2] Sign a File

\[3] Sign a Folder / Software Release

\[4] Verify a File

\[5] Verify a Folder / Software Release

\[6] Inspect File Signature

\[7] Help - How does this tool work?

\[0] Exit

```



\## Installation



Clone the repository and enter the project directory:



```bash

cd 03-Software-Supply-Chain-Artifact-Signer

```



Create a Python virtual environment:



\### Windows



```bash

python -m venv .venv

.venv\\Scripts\\activate

```



Install dependencies:



```bash

python -m pip install -r requirements.txt

```



Run the tool:



```bash

python -m app.main

```



\## Example: Sign a File



Start the application:



```bash

python -m app.main

```



Select:



```text

\[2] Sign a File

```



Then provide the full path to an artifact.



The tool calculates its SHA-256 fingerprint and creates an Ed25519 signature beside the original artifact.



Example:



```text

application.exe

application.exe.sig

```



The artifact can later be verified using:



```text

\[4] Verify a File

```



If the artifact has changed since signing, signature verification fails.



\## Example: Sign a Software Release



A release may contain multiple artifacts:



```text

MySoftware/

├── application.exe

├── library.dll

├── config.json

└── README.txt

```



Select:



```text

\[3] Sign a Folder / Software Release

```



The tool creates a manifest containing the SHA-256 fingerprint of every artifact and digitally signs the manifest.



During verification, the tool can identify:



```text

\[OK]          Unchanged artifact

\[MODIFIED]    Artifact content changed

\[MISSING]     Expected artifact was removed

\[UNEXPECTED]  New artifact was introduced

```



\## Security Model



The project separates two important security properties:



\*\*Manifest authenticity\*\*



Ed25519 verifies that the release manifest was signed by the holder of the corresponding private key and that the signed manifest bytes have not changed.



\*\*Artifact integrity\*\*



SHA-256 fingerprints in the authenticated manifest are compared with the current release artifacts.



Therefore, modifying an artifact does not necessarily invalidate the manifest signature itself. Instead, the manifest remains authentic while the artifact hash comparison detects the modification.



If the manifest itself is modified, Ed25519 signature verification fails.



\## Trust Model



Verification depends on having an authentic copy of the signer's public key.



The public key acts as an external trust anchor and should be distributed through a trusted channel in a real deployment.



\## Security Limitations



This project is an educational cryptographic prototype and is not intended to replace production software-signing infrastructure.



The current implementation:



\- Stores the signing private key locally without encryption.

\- Does not provide certificate-based identity.

\- Does not implement certificate revocation.

\- Does not provide trusted timestamps.

\- Does not use an HSM or dedicated signing service.

\- Does not provide transparency-log integration.

\- Assumes the verifier obtained the public key through a trusted channel.



A production implementation should protect signing keys using secure key storage, an HSM, or a dedicated signing service.



\## Project Structure



```text

03-Software-Supply-Chain-Artifact-Signer/

├── app/

│   ├── hashing.py

│   ├── signing.py

│   ├── manifest.py

│   └── main.py

├── tests/

├── release/

├── .gitignore

├── requirements.txt

└── README.md

```



\## Purpose



This project was developed as part of a practical cryptography portfolio focused on applied cryptographic engineering.



It demonstrates:



\- Cryptographic hashing

\- Digital signatures

\- Key-pair based trust

\- Artifact integrity verification

\- Signed metadata

\- Software supply chain security concepts

\- Tamper detection



\## Disclaimer



For educational and research purposes only.

