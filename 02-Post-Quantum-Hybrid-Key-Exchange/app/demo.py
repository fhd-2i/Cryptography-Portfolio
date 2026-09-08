from pathlib import Path
import secrets

from app.aead import decrypt_message, encrypt_message
from app.hybrid_kdf import derive_hybrid_key
from app.hybrid_kex import HybridKeyExchange
from app.package_format import (
    create_package,
    deserialize_package,
    serialize_package,
)


PACKAGE_FILE = Path("hybrid_message.json")


def main() -> None:
    hybrid = HybridKeyExchange()

    print("=== Recipient Key Generation ===")

    recipient_x_private, recipient_x_public = (
        hybrid.generate_x25519_keypair()
    )

    mlkem_public, mlkem_private = (
        hybrid.generate_mlkem_keypair()
    )

    print("Recipient X25519 key pair generated.")
    print("Recipient ML-KEM-768 key pair generated.")

    print()
    print("=== Sender Hybrid Key Exchange ===")

    sender_x_private, sender_x_public = (
        hybrid.generate_x25519_keypair()
    )

    sender_x_secret = hybrid.x25519_shared_secret(
        sender_x_private,
        recipient_x_public,
    )

    sender_mlkem_secret, kem_ciphertext = (
        hybrid.mlkem_encapsulate(
            mlkem_public
        )
    )

    salt = secrets.token_bytes(16)

    sender_hybrid_key = derive_hybrid_key(
        sender_x_secret,
        sender_mlkem_secret,
        salt,
    )

    print("Sender derived hybrid AES-256 key.")

    print()
    print("=== AES-256-GCM Encryption ===")

    plaintext = (
        b"Post-Quantum Hybrid Cryptography Demo"
    )

    nonce, ciphertext = encrypt_message(
        sender_hybrid_key,
        plaintext,
    )

    print(
        "Plaintext:",
        plaintext.decode(),
    )

    print(
        "Ciphertext:",
        ciphertext.hex(),
    )

    print()
    print("=== Create Hybrid Message Package ===")

    package = create_package(
        sender_x25519_public=sender_x_public,
        mlkem_ciphertext=kem_ciphertext,
        salt=salt,
        nonce=nonce,
        ciphertext=ciphertext,
    )

    serialized_package = serialize_package(
        package
    )

    PACKAGE_FILE.write_text(
        serialized_package,
        encoding="utf-8",
    )

    print(
        "Package saved to:",
        PACKAGE_FILE,
    )

    print()
    print("=== Recipient Reads Package ===")

    package_text = PACKAGE_FILE.read_text(
        encoding="utf-8"
    )

    received = deserialize_package(
        package_text
    )

    print("Package loaded successfully.")

    print()
    print("=== Recipient Hybrid Key Recovery ===")

    recipient_x_secret = hybrid.x25519_shared_secret(
        recipient_x_private,
        received["sender_x25519_public"],
    )

    recipient_mlkem_secret = (
        hybrid.mlkem_decapsulate(
            mlkem_private,
            received["mlkem_ciphertext"],
        )
    )

    recipient_hybrid_key = derive_hybrid_key(
        recipient_x_secret,
        recipient_mlkem_secret,
        received["salt"],
    )

    print(
        "Hybrid keys match:",
        sender_hybrid_key == recipient_hybrid_key,
    )

    print()
    print("=== AES-256-GCM Decryption ===")

    restored_plaintext = decrypt_message(
        recipient_hybrid_key,
        received["nonce"],
        received["ciphertext"],
    )

    print(
        "Recovered plaintext:",
        restored_plaintext.decode(),
    )

    print(
        "Decryption successful:",
        restored_plaintext == plaintext,
    )

    print()
    print("=== Tamper Detection Test ===")

    tampered_ciphertext = bytearray(
        received["ciphertext"]
    )

    tampered_ciphertext[0] ^= 1

    try:
        decrypt_message(
            recipient_hybrid_key,
            received["nonce"],
            bytes(tampered_ciphertext),
        )

        print(
            "Tamper detection failed."
        )

    except ValueError as exc:
        print(
            "Tampering detected successfully."
        )

        print(
            "Reason:",
            exc,
        )


if __name__ == "__main__":
    main()