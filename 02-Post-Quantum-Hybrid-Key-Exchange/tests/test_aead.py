import secrets

import pytest

from app.aead import decrypt_message, encrypt_message


def test_encrypt_decrypt_roundtrip():
    key = secrets.token_bytes(32)
    plaintext = b"Hybrid cryptography test message"

    nonce, ciphertext = encrypt_message(
        key,
        plaintext,
    )

    restored = decrypt_message(
        key,
        nonce,
        ciphertext,
    )

    assert restored == plaintext


def test_ciphertext_is_not_plaintext():
    key = secrets.token_bytes(32)
    plaintext = b"Secret message"

    _, ciphertext = encrypt_message(
        key,
        plaintext,
    )

    assert ciphertext != plaintext


def test_tampered_ciphertext_fails():
    key = secrets.token_bytes(32)

    nonce, ciphertext = encrypt_message(
        key,
        b"Secret message",
    )

    tampered = bytearray(ciphertext)
    tampered[0] ^= 1

    with pytest.raises(ValueError):
        decrypt_message(
            key,
            nonce,
            bytes(tampered),
        )


def test_wrong_key_fails():
    key = secrets.token_bytes(32)
    wrong_key = secrets.token_bytes(32)

    nonce, ciphertext = encrypt_message(
        key,
        b"Secret message",
    )

    with pytest.raises(ValueError):
        decrypt_message(
            wrong_key,
            nonce,
            ciphertext,
        )


def test_wrong_nonce_fails():
    key = secrets.token_bytes(32)

    nonce, ciphertext = encrypt_message(
        key,
        b"Secret message",
    )

    wrong_nonce = bytearray(nonce)
    wrong_nonce[0] ^= 1

    with pytest.raises(ValueError):
        decrypt_message(
            key,
            bytes(wrong_nonce),
            ciphertext,
        )


def test_invalid_key_size_rejected():
    with pytest.raises(ValueError):
        encrypt_message(
            b"short-key",
            b"data",
        )


def test_invalid_nonce_size_rejected():
    key = secrets.token_bytes(32)

    with pytest.raises(ValueError):
        decrypt_message(
            key,
            b"short",
            b"ciphertext",
        )