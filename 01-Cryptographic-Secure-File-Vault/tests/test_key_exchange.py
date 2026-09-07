import pytest

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)

from app.ecc import (
    generate_key_pair,
    derive_shared_secret,
    serialize_public_key,
)

from app.hashing import (
    derive_key,
)


def test_x25519_key_pair_generation():
    """X25519 must generate a valid private/public key pair."""

    private_key, public_key = generate_key_pair()

    assert isinstance(
        private_key,
        X25519PrivateKey,
    )

    assert len(
        serialize_public_key(public_key)
    ) == 32


def test_x25519_shared_secret_matches():
    """
    Both parties must derive the same shared secret
    using X25519 ECDH.
    """

    alice_private, alice_public = (
        generate_key_pair()
    )

    bob_private, bob_public = (
        generate_key_pair()
    )

    alice_secret = derive_shared_secret(
        alice_private,
        bob_public,
    )

    bob_secret = derive_shared_secret(
        bob_private,
        alice_public,
    )

    assert alice_secret == bob_secret
    assert len(alice_secret) == 32


def test_x25519_different_keys_produce_different_secret():
    """Different X25519 key pairs must not produce the same secret."""

    alice_private, _ = (
        generate_key_pair()
    )

    bob_private, bob_public = (
        generate_key_pair()
    )

    another_private, another_public = (
        generate_key_pair()
    )

    secret_one = derive_shared_secret(
        alice_private,
        bob_public,
    )

    secret_two = derive_shared_secret(
        another_private,
        bob_public,
    )

    secret_three = derive_shared_secret(
        alice_private,
        another_public,
    )

    assert secret_one != secret_two
    assert secret_one != secret_three


def test_hkdf_derives_32_byte_key():
    """HKDF-SHA256 must derive a 32-byte key."""

    shared_secret = b"A" * 32

    derived_key = derive_key(
        shared_secret,
    )

    assert len(derived_key) == 32


def test_hkdf_same_input_produces_same_key():
    """Same input, salt and info must produce the same derived key."""

    shared_secret = b"A" * 32
    salt = b"B" * 16
    info = b"test-context"

    key_one = derive_key(
        shared_secret,
        salt=salt,
        info=info,
    )

    key_two = derive_key(
        shared_secret,
        salt=salt,
        info=info,
    )

    assert key_one == key_two


def test_hkdf_different_salt_produces_different_key():
    """Changing the HKDF salt must change the derived key."""

    shared_secret = b"A" * 32

    key_one = derive_key(
        shared_secret,
        salt=b"B" * 16,
    )

    key_two = derive_key(
        shared_secret,
        salt=b"C" * 16,
    )

    assert key_one != key_two


def test_hkdf_different_info_produces_different_key():
    """Changing HKDF context information must change the derived key."""

    shared_secret = b"A" * 32
    salt = b"B" * 16

    key_one = derive_key(
        shared_secret,
        salt=salt,
        info=b"context-one",
    )

    key_two = derive_key(
        shared_secret,
        salt=salt,
        info=b"context-two",
    )

    assert key_one != key_two


def test_hkdf_different_secret_produces_different_key():
    """Different shared secrets must produce different derived keys."""

    salt = b"B" * 16
    info = b"test-context"

    key_one = derive_key(
        b"A" * 32,
        salt=salt,
        info=info,
    )

    key_two = derive_key(
        b"C" * 32,
        salt=salt,
        info=info,
    )

    assert key_one != key_two