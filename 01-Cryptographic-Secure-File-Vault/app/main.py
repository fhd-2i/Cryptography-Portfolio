import argparse
from getpass import getpass
from pathlib import Path

from app.identity import (
    initialize_identity,
    load_x25519_private_key,
    load_x25519_public_key,
    load_ed25519_private_key,
    load_ed25519_public_key,
)

from app.vault_engine import (
    create_vault,
    decrypt_vault,
)


DEFAULT_KEYS_DIRECTORY = "keys"


def command_init() -> None:
    """Initialize the cryptographic identity."""

    print("========================================")
    print(" Cryptographic Secure Vault - Init")
    print("========================================")
    print()

    keys_directory = Path(
        DEFAULT_KEYS_DIRECTORY
    )

    if keys_directory.exists() and any(
        keys_directory.iterdir()
    ):
        raise FileExistsError(
            "Cryptographic identity already exists. "
            "Initialization was not performed."
        )

    password = getpass(
        "Create a password for your cryptographic identity: "
    )

    confirm_password = getpass(
        "Confirm password: "
    )

    if not password:
        raise ValueError(
            "Password cannot be empty."
        )

    if password != confirm_password:
        raise ValueError(
            "Passwords do not match."
        )

    initialize_identity(
        password,
        DEFAULT_KEYS_DIRECTORY,
    )

    print()
    print("Identity initialization complete.")


def command_encrypt(
    input_path: str,
    output_path: str,
) -> None:
    """Encrypt a file into a cryptographic vault."""

    print("========================================")
    print(" Cryptographic Secure Vault - Encrypt")
    print("========================================")
    print()

    input_file = Path(
        input_path
    )

    output_file = Path(
        output_path
    )

    keys_directory = Path(
        DEFAULT_KEYS_DIRECTORY
    )

    if not input_file.exists():
        raise FileNotFoundError(
            f"Input file not found: {input_path}"
        )

    if not input_file.is_file():
        raise ValueError(
            f"Input path is not a regular file: {input_path}"
        )

    if output_file.exists():
        raise FileExistsError(
            f"Output file already exists: {output_path}"
        )

    if not keys_directory.exists():
        raise FileNotFoundError(
            "Cryptographic identity not found. "
            "Run 'init' first."
        )

    password = getpass(
        "Enter your cryptographic password: "
    )

    recipient_public_key = load_x25519_public_key(
        DEFAULT_KEYS_DIRECTORY
    )

    signing_private_key = load_ed25519_private_key(
        password,
        DEFAULT_KEYS_DIRECTORY,
    )

    create_vault(
        input_path,
        output_path,
        recipient_public_key,
        signing_private_key,
    )

    print()
    print("Encryption completed successfully.")
    print(f"Input : {input_path}")
    print(f"Output: {output_path}")


def command_decrypt(
    input_path: str,
    output_path: str,
) -> None:
    """Decrypt and verify a cryptographic vault."""

    print("========================================")
    print(" Cryptographic Secure Vault - Decrypt")
    print("========================================")
    print()

    input_file = Path(
        input_path
    )

    output_file = Path(
        output_path
    )

    keys_directory = Path(
        DEFAULT_KEYS_DIRECTORY
    )

    if not input_file.exists():
        raise FileNotFoundError(
            f"Vault file not found: {input_path}"
        )

    if not input_file.is_file():
        raise ValueError(
            f"Vault path is not a regular file: {input_path}"
        )

    if output_file.exists():
        raise FileExistsError(
            f"Output file already exists: {output_path}"
        )

    if not keys_directory.exists():
        raise FileNotFoundError(
            "Cryptographic identity not found. "
            "Run 'init' first."
        )

    password = getpass(
        "Enter your cryptographic password: "
    )

    recipient_private_key = load_x25519_private_key(
        password,
        DEFAULT_KEYS_DIRECTORY,
    )

    trusted_signing_public_key = (
        load_ed25519_public_key(
            DEFAULT_KEYS_DIRECTORY
        )
    )

    decrypt_vault(
        input_path,
        output_path,
        recipient_private_key,
        trusted_signing_public_key,
    )

    print()
    print("Decryption completed successfully.")
    print(f"Input : {input_path}")
    print(f"Output: {output_path}")


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""

    parser = argparse.ArgumentParser(
        prog="cryptographic-secure-vault",
        description=(
            "Cryptographic Secure File Vault using "
            "AES-256-GCM, X25519, HKDF-SHA256, "
            "and Ed25519."
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    subparsers.add_parser(
        "init",
        help="Initialize cryptographic identity.",
    )

    encrypt_parser = subparsers.add_parser(
        "encrypt",
        help="Encrypt a file into a vault.",
    )

    encrypt_parser.add_argument(
        "input",
        help="Path to the plaintext file.",
    )

    encrypt_parser.add_argument(
        "output",
        help="Path to the output .vault file.",
    )

    decrypt_parser = subparsers.add_parser(
        "decrypt",
        help="Decrypt a vault.",
    )

    decrypt_parser.add_argument(
        "input",
        help="Path to the .vault file.",
    )

    decrypt_parser.add_argument(
        "output",
        help="Path to the restored file.",
    )

    return parser


def main() -> None:
    """CLI entry point."""

    parser = build_parser()
    args = parser.parse_args()

    try:

        if args.command == "init":
            command_init()

        elif args.command == "encrypt":
            command_encrypt(
                args.input,
                args.output,
            )

        elif args.command == "decrypt":
            command_decrypt(
                args.input,
                args.output,
            )

    except Exception as exc:

        print()
        print(f"ERROR: {exc}")

        raise SystemExit(1)


if __name__ == "__main__":
    main()