import pytest

from app.aes import (
    KEY_SIZE,
    NONCE_SIZE,
    generate_key,
    encrypt_data,
    decrypt_data,
)


def test_generate_key_size():
    """AES key must be exactly 32 bytes."""

    key = generate_key()

    assert len(key) == KEY_SIZE
    assert KEY_SIZE == 32


def test_aes_round_trip():
    """AES-256-GCM must recover the original plaintext."""

    key = generate_key()

    plaintext = (
        b"Confidential AES-256-GCM test data"
    )

    nonce, ciphertext = encrypt_data(
        plaintext,
        key,
    )

    decrypted = decrypt_data(
        ciphertext,
        key,
        nonce,
    )

    assert decrypted == plaintext


def test_aes_nonce_size():
    """AES-GCM nonce must be exactly 12 bytes."""

    key = generate_key()

    nonce, _ = encrypt_data(
        b"Test data",
        key,
    )

    assert len(nonce) == NONCE_SIZE
    assert NONCE_SIZE == 12


def test_aes_wrong_key_rejected():
    """Decrypting with a different key must fail."""

    key = generate_key()
    wrong_key = generate_key()

    nonce, ciphertext = encrypt_data(
        b"Secret data",
        key,
    )

    with pytest.raises(Exception):
        decrypt_data(
            ciphertext,
            wrong_key,
            nonce,
        )


def test_aes_tampered_ciphertext_rejected():
    """Modified ciphertext must fail authentication."""

    key = generate_key()

    nonce, ciphertext = encrypt_data(
        b"Secret data",
        key,
    )

    tampered = (
        ciphertext[:-1]
        + bytes(
            [ciphertext[-1] ^ 1]
        )
    )

    with pytest.raises(Exception):
        decrypt_data(
            tampered,
            key,
            nonce,
        )


def test_aes_invalid_key_length_rejected():
    """AES-256-GCM must reject keys that are not 32 bytes."""

    invalid_key = b"short-key"

    with pytest.raises(
        ValueError,
        match="32 bytes",
    ):
        encrypt_data(
            b"Test data",
            invalid_key,
        )


def test_aes_invalid_nonce_length_rejected():
    """AES-GCM must reject invalid nonce lengths."""

    key = generate_key()

    nonce, ciphertext = encrypt_data(
        b"Test data",
        key,
    )

    invalid_nonce = nonce[:-1]

    with pytest.raises(
        ValueError,
        match="12 bytes",
    ):
        decrypt_data(
            ciphertext,
            key,
            invalid_nonce,
        )


def test_aes_associated_data_authentication():
    """
    AES-GCM associated data must be authenticated.

    Changing associated data must cause decryption failure.
    """

    key = generate_key()

    associated_data = (
        b"vault-metadata"
    )

    nonce, ciphertext = encrypt_data(
        b"Secret data",
        key,
        associated_data,
    )

    decrypted = decrypt_data(
        ciphertext,
        key,
        nonce,
        associated_data,
    )

    assert decrypted == b"Secret data"

    with pytest.raises(Exception):
        decrypt_data(
            ciphertext,
            key,
            nonce,
            b"modified-metadata",
        )