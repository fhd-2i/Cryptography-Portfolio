from pathlib import Path
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from app.aes import KEY_SIZE


SALT_SIZE = 16
NONCE_SIZE = 12

SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1


def derive_key_from_password(
    password: str,
    salt: bytes,
) -> bytes:
    """Derive a 256-bit key from a password using Scrypt."""

    if not password:
        raise ValueError(
            "Password cannot be empty."
        )

    if len(salt) != SALT_SIZE:
        raise ValueError(
            "Salt must be exactly 16 bytes."
        )

    kdf = Scrypt(
        salt=salt,
        length=KEY_SIZE,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )

    return kdf.derive(
        password.encode("utf-8")
    )


def protect_private_key(
    private_key: bytes,
    password: str,
    output_path: str,
) -> None:
    """
    Encrypt a private key using:

        Password
           ↓
        Scrypt
           ↓
      AES-256-GCM
           ↓
    Protected key file

    Stored format:

        salt + nonce + ciphertext
    """

    if not private_key:
        raise ValueError(
            "Private key cannot be empty."
        )

    salt = secrets.token_bytes(
        SALT_SIZE
    )

    password_key = derive_key_from_password(
        password,
        salt,
    )

    nonce = secrets.token_bytes(
        NONCE_SIZE
    )

    aesgcm = AESGCM(
        password_key
    )

    ciphertext = aesgcm.encrypt(
        nonce,
        private_key,
        None,
    )

    Path(output_path).write_bytes(
        salt + nonce + ciphertext
    )


def load_protected_private_key(
    input_path: str,
    password: str,
) -> bytes:
    """Load and decrypt a password-protected private key."""

    data = Path(input_path).read_bytes()

    minimum_size = (
        SALT_SIZE
        + NONCE_SIZE
        + 16
    )

    if len(data) < minimum_size:
        raise ValueError(
            "Invalid protected private key file."
        )

    salt = data[:SALT_SIZE]

    nonce_start = SALT_SIZE
    nonce_end = nonce_start + NONCE_SIZE

    nonce = data[
        nonce_start:nonce_end
    ]

    ciphertext = data[
        nonce_end:
    ]

    password_key = derive_key_from_password(
        password,
        salt,
    )

    aesgcm = AESGCM(
        password_key
    )

    return aesgcm.decrypt(
        nonce,
        ciphertext,
        None,
    )


def wrap_key(
    file_key: bytes,
    wrapping_key: bytes,
) -> tuple[bytes, bytes]:
    """Protect an AES file key using AES-256-GCM."""

    if len(file_key) != KEY_SIZE:
        raise ValueError(
            "File key must be exactly 32 bytes."
        )

    if len(wrapping_key) != KEY_SIZE:
        raise ValueError(
            "Wrapping key must be exactly 32 bytes."
        )

    nonce = secrets.token_bytes(
        NONCE_SIZE
    )

    aesgcm = AESGCM(
        wrapping_key
    )

    wrapped_key = aesgcm.encrypt(
        nonce,
        file_key,
        None,
    )

    return nonce, wrapped_key


def unwrap_key(
    wrapped_key: bytes,
    wrapping_key: bytes,
    nonce: bytes,
) -> bytes:
    """Recover the original AES file encryption key."""

    if len(wrapping_key) != KEY_SIZE:
        raise ValueError(
            "Wrapping key must be exactly 32 bytes."
        )

    if len(nonce) != NONCE_SIZE:
        raise ValueError(
            "Invalid wrapping nonce."
        )

    aesgcm = AESGCM(
        wrapping_key
    )

    file_key = aesgcm.decrypt(
        nonce,
        wrapped_key,
        None,
    )

    if len(file_key) != KEY_SIZE:
        raise ValueError(
            "Recovered key is invalid."
        )

    return file_key