from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from app.ecc import generate_key_pair
from app.signatures import generate_signing_key_pair
from app.key_management import (
    protect_private_key,
    load_protected_private_key,
)


def serialize_x25519_private_key(
    private_key: X25519PrivateKey,
) -> bytes:
    """Serialize an X25519 private key."""

    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serialize_ed25519_private_key(
    private_key: Ed25519PrivateKey,
) -> bytes:
    """Serialize an Ed25519 private key."""

    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serialize_x25519_public_key(
    private_key: X25519PrivateKey,
) -> bytes:
    """Serialize an X25519 public key."""

    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def serialize_ed25519_public_key(
    private_key: Ed25519PrivateKey,
) -> bytes:
    """Serialize an Ed25519 public key."""

    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def initialize_identity(
    password: str,
    keys_directory: str = "keys",
) -> None:
    """
    Generate the user's cryptographic identity.

    X25519:
        Used for ECDH key agreement.

    Ed25519:
        Used for digital signatures.

    Private keys are protected with:
        Scrypt + AES-256-GCM
    """

    if not password:
        raise ValueError("Password cannot be empty.")

    keys_path = Path(keys_directory)
    keys_path.mkdir(parents=True, exist_ok=True)

    # Generate X25519 identity
    x25519_private, _ = generate_key_pair()

    # Generate Ed25519 signing identity
    ed25519_private, _ = generate_signing_key_pair()

    # Serialize private keys
    x25519_private_bytes = serialize_x25519_private_key(
        x25519_private
    )

    ed25519_private_bytes = serialize_ed25519_private_key(
        ed25519_private
    )

    # Serialize public keys
    x25519_public_bytes = serialize_x25519_public_key(
        x25519_private
    )

    ed25519_public_bytes = serialize_ed25519_public_key(
        ed25519_private
    )

    # Protect private keys
    protect_private_key(
        x25519_private_bytes,
        password,
        str(keys_path / "x25519_private.key"),
    )

    protect_private_key(
        ed25519_private_bytes,
        password,
        str(keys_path / "ed25519_private.key"),
    )

    # Save public keys
    (keys_path / "x25519_public.key").write_bytes(
        x25519_public_bytes
    )

    (keys_path / "ed25519_public.key").write_bytes(
        ed25519_public_bytes
    )

    print("Cryptographic identity initialized successfully.")
    print()
    print("Generated:")
    print("  X25519 private key  -> keys/x25519_private.key")
    print("  X25519 public key   -> keys/x25519_public.key")
    print("  Ed25519 private key -> keys/ed25519_private.key")
    print("  Ed25519 public key  -> keys/ed25519_public.key")


def load_x25519_private_key(
    password: str,
    keys_directory: str = "keys",
) -> X25519PrivateKey:
    """Load and decrypt the X25519 private key."""

    path = Path(keys_directory) / "x25519_private.key"

    private_key_bytes = load_protected_private_key(
        str(path),
        password,
    )

    if len(private_key_bytes) != 32:
        raise ValueError("Invalid X25519 private key.")

    return X25519PrivateKey.from_private_bytes(
        private_key_bytes
    )


def load_ed25519_private_key(
    password: str,
    keys_directory: str = "keys",
) -> Ed25519PrivateKey:
    """Load and decrypt the Ed25519 private key."""

    path = Path(keys_directory) / "ed25519_private.key"

    private_key_bytes = load_protected_private_key(
        str(path),
        password,
    )

    if len(private_key_bytes) != 32:
        raise ValueError("Invalid Ed25519 private key.")

    return Ed25519PrivateKey.from_private_bytes(
        private_key_bytes
    )


def load_x25519_public_key(
    keys_directory: str = "keys",
) -> X25519PublicKey:
    """Load the X25519 public key."""

    path = Path(keys_directory) / "x25519_public.key"

    public_key_bytes = path.read_bytes()

    if len(public_key_bytes) != 32:
        raise ValueError("Invalid X25519 public key.")

    return X25519PublicKey.from_public_bytes(
        public_key_bytes
    )


def load_ed25519_public_key(
    keys_directory: str = "keys",
) -> Ed25519PublicKey:
    """Load the Ed25519 public key."""

    path = Path(keys_directory) / "ed25519_public.key"

    public_key_bytes = path.read_bytes()

    if len(public_key_bytes) != 32:
        raise ValueError("Invalid Ed25519 public key.")

    return Ed25519PublicKey.from_public_bytes(
        public_key_bytes
    )