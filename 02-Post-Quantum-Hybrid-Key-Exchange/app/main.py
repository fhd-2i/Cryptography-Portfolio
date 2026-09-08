import argparse
import json
import secrets
from pathlib import Path

from app.aead import decrypt_message, encrypt_message
from app.hybrid_kdf import derive_hybrid_key
from app.hybrid_kex import HybridKeyExchange
from app.identity import (
    PUBLIC_KEY_FILE,
    PRIVATE_KEY_FILE,
    create_recipient_identity,
    load_private_identity,
    load_public_identity,
)
from app.package_format import (
    create_package,
    deserialize_package,
    serialize_package,
)


DEFAULT_OUTPUT = Path("encrypted_message.hybrid")


def initialize_identity() -> None:
    create_recipient_identity()

    print()
    print("=== Recipient Identity Created ===")
    print()
    print("Classical algorithm : X25519")
    print("Post-quantum KEM    : ML-KEM-768")
    print()
    print("Public identity :", PUBLIC_KEY_FILE)
    print("Private identity:", PRIVATE_KEY_FILE)
    print()
    print("[+] Recipient cryptographic identity generated successfully.")
    print()
    print(
        "[!] This prototype stores private key material locally "
        "without password protection."
    )


def encrypt_text(message: str, output_file: Path) -> None:
    hybrid = HybridKeyExchange()

    recipient_x_public, recipient_mlkem_public = (
        load_public_identity()
    )

    print()
    print("=== Hybrid Encryption ===")
    print()
    print("[1] Loaded recipient public keys")
    print("    - X25519 public key")
    print("    - ML-KEM-768 encapsulation key")

    sender_x_private, sender_x_public = (
        hybrid.generate_x25519_keypair()
    )

    print()
    print("[2] Generated ephemeral sender X25519 key pair")

    x25519_secret = hybrid.x25519_shared_secret(
        sender_x_private,
        recipient_x_public,
    )

    print("[3] Established classical X25519 shared secret")

    mlkem_secret, mlkem_ciphertext = (
        hybrid.mlkem_encapsulate(
            recipient_mlkem_public
        )
    )

    print("[4] Established post-quantum ML-KEM-768 shared secret")

    salt = secrets.token_bytes(16)

    hybrid_key = derive_hybrid_key(
        x25519_secret,
        mlkem_secret,
        salt,
    )

    print("[5] Combined both secrets using HKDF-SHA256")
    print("[6] Derived 256-bit hybrid session key")

    nonce, ciphertext = encrypt_message(
        hybrid_key,
        message.encode("utf-8"),
    )

    print("[7] Encrypted message using AES-256-GCM")

    package = create_package(
        sender_x25519_public=sender_x_public,
        mlkem_ciphertext=mlkem_ciphertext,
        salt=salt,
        nonce=nonce,
        ciphertext=ciphertext,
    )

    output_file.write_text(
        serialize_package(package),
        encoding="utf-8",
    )

    print()
    print("=== Encryption Result ===")
    print()
    print("Original message :", message)
    print("Output package   :", output_file)
    print("Ciphertext size  :", len(ciphertext), "bytes")
    print()
    print("[+] Hybrid encryption completed successfully.")


def decrypt_file(input_file: Path) -> None:
    if not input_file.exists():
        raise FileNotFoundError(
            f"Encrypted package not found: {input_file}"
        )

    hybrid = HybridKeyExchange()

    recipient_x_private, recipient_mlkem_private = (
        load_private_identity()
    )

    package = deserialize_package(
        input_file.read_text(encoding="utf-8")
    )

    print()
    print("=== Hybrid Decryption ===")
    print()
    print("[1] Loaded encrypted hybrid package")
    print("[2] Loaded recipient private keys")

    x25519_secret = hybrid.x25519_shared_secret(
        recipient_x_private,
        package["sender_x25519_public"],
    )

    print("[3] Recovered classical X25519 shared secret")

    mlkem_secret = hybrid.mlkem_decapsulate(
        recipient_mlkem_private,
        package["mlkem_ciphertext"],
    )

    print("[4] Recovered post-quantum ML-KEM-768 shared secret")

    hybrid_key = derive_hybrid_key(
        x25519_secret,
        mlkem_secret,
        package["salt"],
    )

    print("[5] Re-derived 256-bit hybrid session key")

    plaintext = decrypt_message(
        hybrid_key,
        package["nonce"],
        package["ciphertext"],
    )

    print("[6] AES-256-GCM authentication verified")
    print("[7] Message decrypted successfully")

    print()
    print("=== Decryption Result ===")
    print()
    print("Recovered message:")
    print()
    print(plaintext.decode("utf-8"))
    print()
    print("[+] Confidentiality and integrity verification successful.")


def inspect_package(input_file: Path) -> None:
    if not input_file.exists():
        raise FileNotFoundError(
            f"Package not found: {input_file}"
        )

    raw_data = json.loads(
        input_file.read_text(encoding="utf-8")
    )

    print()
    print("=== Hybrid Package Inspection ===")
    print()
    print("File       :", input_file)
    print("Version    :", raw_data.get("version"))
    print()

    algorithms = raw_data.get("algorithms", {})

    print("Algorithms:")
    print(
        "  Classical KEX :",
        algorithms.get("classical_kex"),
    )
    print(
        "  Post-Quantum  :",
        algorithms.get("post_quantum_kem"),
    )
    print(
        "  KDF           :",
        algorithms.get("kdf"),
    )
    print(
        "  Encryption    :",
        algorithms.get("aead"),
    )

    print()
    print("Package fields:")
    print("  sender_x25519_public")
    print("  mlkem_ciphertext")
    print("  salt")
    print("  nonce")
    print("  ciphertext")

    print()
    print(
        "[+] No plaintext message or private key is stored "
        "inside the package."
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Post-Quantum Hybrid Key Exchange "
            "using X25519 + ML-KEM-768."
        )
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    subparsers.add_parser(
        "init",
        help="Generate recipient classical and post-quantum keys.",
    )

    encrypt_parser = subparsers.add_parser(
        "encrypt",
        help="Encrypt a text message for the recipient.",
    )

    encrypt_parser.add_argument(
        "message",
        help="Text message to encrypt.",
    )

    encrypt_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output hybrid package.",
    )

    decrypt_parser = subparsers.add_parser(
        "decrypt",
        help="Decrypt a hybrid encrypted package.",
    )

    decrypt_parser.add_argument(
        "file",
        type=Path,
        help="Hybrid package to decrypt.",
    )

    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Inspect cryptographic metadata in a package.",
    )

    inspect_parser.add_argument(
        "file",
        type=Path,
        help="Hybrid package to inspect.",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "init":
            initialize_identity()

        elif args.command == "encrypt":
            encrypt_text(
                args.message,
                args.output,
            )

        elif args.command == "decrypt":
            decrypt_file(
                args.file
            )

        elif args.command == "inspect":
            inspect_package(
                args.file
            )

    except Exception as exc:
        print()
        print("[ERROR]", exc)


if __name__ == "__main__":
    main()