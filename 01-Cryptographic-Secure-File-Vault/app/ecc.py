from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


def generate_key_pair() -> tuple[
    X25519PrivateKey,
    X25519PublicKey,
]:
    """Generate an X25519 private/public key pair."""

    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    return private_key, public_key


def derive_shared_secret(
    private_key: X25519PrivateKey,
    peer_public_key: X25519PublicKey,
) -> bytes:
    """Derive a shared secret using X25519 ECDH."""

    return private_key.exchange(peer_public_key)


def serialize_public_key(
    public_key: X25519PublicKey,
) -> bytes:
    """Serialize an X25519 public key."""

    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )