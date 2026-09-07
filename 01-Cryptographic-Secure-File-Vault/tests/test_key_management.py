import pytest

from app.key_management import (
    SALT_SIZE,
    NONCE_SIZE,
    derive_key_from_password,
    protect_private_key,
    load_protected_private_key,
    wrap_key,
    unwrap_key,
)

from app.aes import generate_key


PASSWORD = "StrongTestPassword123!"


def test_scrypt_derives_32_byte_key():
    """Scrypt must derive a 256-bit key."""

    salt = b"A" * SALT_SIZE

    derived_key = derive_key_from_password(
        PASSWORD,
        salt,
    )

    assert len(derived_key) == 32


def test_scrypt_same_password_and_salt():
    """Same password and salt must produce the same key."""

    salt = b"A" * SALT_SIZE

    key_one = derive_key_from_password(
        PASSWORD,
        salt,
    )

    key_two = derive_key_from_password(
        PASSWORD,
        salt,
    )

    assert key_one == key_two


def test_scrypt_different_salt():
    """Changing the salt must change the derived key."""

    key_one = derive_key_from_password(
        PASSWORD,
        b"A" * SALT_SIZE,
    )

    key_two = derive_key_from_password(
        PASSWORD,
        b"B" * SALT_SIZE,
    )

    assert key_one != key_two


def test_scrypt_different_password():
    """Changing the password must change the derived key."""

    salt = b"A" * SALT_SIZE

    key_one = derive_key_from_password(
        PASSWORD,
        salt,
    )

    key_two = derive_key_from_password(
        "DifferentPassword456!",
        salt,
    )

    assert key_one != key_two


def test_protected_private_key_round_trip(tmp_path):
    """A protected private key must be recoverable with the correct password."""

    private_key = generate_key()

    key_file = tmp_path / "private.key"

    protect_private_key(
        private_key,
        PASSWORD,
        str(key_file),
    )

    restored_key = load_protected_private_key(
        str(key_file),
        PASSWORD,
    )

    assert restored_key == private_key


def test_protected_private_key_wrong_password():
    """A wrong password must fail to decrypt the protected key."""

    private_key = generate_key()

    key_file = "test_protected.key"

    try:
        protect_private_key(
            private_key,
            PASSWORD,
            key_file,
        )

        with pytest.raises(Exception):
            load_protected_private_key(
                key_file,
                "WrongPassword123!",
            )

    finally:
        import os

        if os.path.exists(key_file):
            os.remove(key_file)


def test_protected_private_key_uses_random_salt_and_nonce(tmp_path):
    """Protecting the same key twice must produce different ciphertext."""

    private_key = generate_key()

    key_file_one = tmp_path / "private1.key"
    key_file_two = tmp_path / "private2.key"

    protect_private_key(
        private_key,
        PASSWORD,
        str(key_file_one),
    )

    protect_private_key(
        private_key,
        PASSWORD,
        str(key_file_two),
    )

    encrypted_one = key_file_one.read_bytes()
    encrypted_two = key_file_two.read_bytes()

    assert encrypted_one != encrypted_two

    assert len(encrypted_one) > (
        SALT_SIZE + NONCE_SIZE
    )


def test_key_wrap_round_trip():
    """A wrapped AES file key must be recoverable."""

    file_key = generate_key()
    wrapping_key = generate_key()

    nonce, wrapped_key = wrap_key(
        file_key,
        wrapping_key,
    )

    restored_key = unwrap_key(
        wrapped_key,
        wrapping_key,
        nonce,
    )

    assert restored_key == file_key


def test_key_wrap_wrong_key_rejected():
    """A wrapped key must not decrypt with a different wrapping key."""

    file_key = generate_key()
    wrapping_key = generate_key()
    wrong_wrapping_key = generate_key()

    nonce, wrapped_key = wrap_key(
        file_key,
        wrapping_key,
    )

    with pytest.raises(Exception):
        unwrap_key(
            wrapped_key,
            wrong_wrapping_key,
            nonce,
        )


def test_key_wrap_tampering_rejected():
    """Tampering with the wrapped key must fail authentication."""

    file_key = generate_key()
    wrapping_key = generate_key()

    nonce, wrapped_key = wrap_key(
        file_key,
        wrapping_key,
    )

    tampered = (
        wrapped_key[:-1]
        + bytes(
            [wrapped_key[-1] ^ 1]
        )
    )

    with pytest.raises(Exception):
        unwrap_key(
            tampered,
            wrapping_key,
            nonce,
        )