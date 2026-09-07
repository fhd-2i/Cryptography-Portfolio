from cryptography.exceptions import InvalidSignature

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate_signing_key_pair() -> tuple[
    Ed25519PrivateKey,
    Ed25519PublicKey,
]:
    """Generate an Ed25519 signing key pair."""

    private_key = (
        Ed25519PrivateKey.generate()
    )

    public_key = (
        private_key.public_key()
    )

    return (
        private_key,
        public_key,
    )


def sign_data(
    data: bytes,
    private_key: Ed25519PrivateKey,
) -> bytes:
    """Create an Ed25519 digital signature."""

    return private_key.sign(
        data
    )


def verify_signature(
    data: bytes,
    signature: bytes,
    public_key: Ed25519PublicKey,
) -> bool:
    """
    Verify an Ed25519 digital signature.

    Returns True when the signature is valid,
    otherwise returns False.
    """

    try:

        public_key.verify(
            signature,
            data,
        )

        return True

    except InvalidSignature:

        return False