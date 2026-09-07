import pytest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from app.signatures import (
    generate_signing_key_pair,
    sign_data,
    verify_signature,
)

from app.vault_engine import calculate_file_hash


def test_ed25519_key_pair_generation():
    """Ed25519 must generate a valid signing key pair."""

    private_key, public_key = (
        generate_signing_key_pair()
    )

    assert isinstance(
        private_key,
        Ed25519PrivateKey,
    )

    assert public_key is not None


def test_ed25519_sign_and_verify():
    """A valid Ed25519 signature must verify successfully."""

    private_key, public_key = (
        generate_signing_key_pair()
    )

    data = b"Cryptographic Secure Vault"

    signature = sign_data(
        data,
        private_key,
    )

    assert len(signature) == 64

    assert verify_signature(
        data,
        signature,
        public_key,
    )


def test_ed25519_tampered_data_rejected():
    """Changing signed data must invalidate the signature."""

    private_key, public_key = (
        generate_signing_key_pair()
    )

    data = b"Original message"

    signature = sign_data(
        data,
        private_key,
    )

    tampered_data = b"Modified message"

    assert not verify_signature(
        tampered_data,
        signature,
        public_key,
    )


def test_ed25519_tampered_signature_rejected():
    """Changing the signature must cause verification failure."""

    private_key, public_key = (
        generate_signing_key_pair()
    )

    data = b"Important message"

    signature = sign_data(
        data,
        private_key,
    )

    tampered_signature = (
        signature[:-1]
        + bytes(
            [signature[-1] ^ 1]
        )
    )

    assert not verify_signature(
        data,
        tampered_signature,
        public_key,
    )


def test_ed25519_wrong_public_key_rejected():
    """A signature must not verify with another public key."""

    private_key, _ = (
        generate_signing_key_pair()
    )

    _, wrong_public_key = (
        generate_signing_key_pair()
    )

    data = b"Secret message"

    signature = sign_data(
        data,
        private_key,
    )

    assert not verify_signature(
        data,
        signature,
        wrong_public_key,
    )


def test_ed25519_signature_is_deterministic():
    """Ed25519 signatures for identical data must be identical."""

    private_key, public_key = (
        generate_signing_key_pair()
    )

    data = b"Deterministic signature test"

    signature_one = sign_data(
        data,
        private_key,
    )

    signature_two = sign_data(
        data,
        private_key,
    )

    assert signature_one == signature_two

    assert verify_signature(
        data,
        signature_one,
        public_key,
    )


def test_sha256_hash_length():
    """SHA-256 must produce a 64-character hexadecimal digest."""

    data = b"Confidential information"

    file_hash = calculate_file_hash(
        data
    )

    assert len(file_hash) == 64

    assert all(
        character in "0123456789abcdef"
        for character in file_hash
    )


def test_sha256_same_data_same_hash():
    """Identical data must produce the same SHA-256 hash."""

    data = b"Same content"

    hash_one = calculate_file_hash(
        data
    )

    hash_two = calculate_file_hash(
        data
    )

    assert hash_one == hash_two


def test_sha256_different_data_different_hash():
    """Different data should produce different SHA-256 hashes."""

    hash_one = calculate_file_hash(
        b"Content A"
    )

    hash_two = calculate_file_hash(
        b"Content B"
    )

    assert hash_one != hash_two


def test_sha256_known_value():
    """Verify SHA-256 against a known test vector."""

    file_hash = calculate_file_hash(
        b"hello"
    )

    assert (
        file_hash
        == "2cf24dba5fb0a30e26e83b2ac5b9e29e"
        "1b161e5c1fa7425e73043362938b9824"
    )