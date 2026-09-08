import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


NONCE_SIZE = 12
AAD = b"PQ-HYBRID-KEX-v1"


def encrypt_message(
    key: bytes,
    plaintext: bytes,
) -> tuple[bytes, bytes]:
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key.")

    nonce = os.urandom(NONCE_SIZE)

    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext,
        AAD,
    )

    return nonce, ciphertext


def decrypt_message(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
) -> bytes:
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key.")

    if len(nonce) != NONCE_SIZE:
        raise ValueError("AES-GCM nonce must be 12 bytes.")

    aesgcm = AESGCM(key)

    try:
        return aesgcm.decrypt(
            nonce,
            ciphertext,
            AAD,
        )
    except InvalidTag as exc:
        raise ValueError(
            "Decryption failed: authentication tag verification failed."
        ) from exc