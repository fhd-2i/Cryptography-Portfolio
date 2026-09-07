from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets


KEY_SIZE = 32       # 32 bytes = 256 bits
NONCE_SIZE = 12     # Recommended nonce size for AES-GCM


def generate_key() -> bytes:
    """Generate a secure random 256-bit AES key."""
    return secrets.token_bytes(KEY_SIZE)


def encrypt_data(
    data: bytes,
    key: bytes,
    associated_data: bytes | None = None
) -> tuple[bytes, bytes]:
    """Encrypt data using AES-256-GCM."""

    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 key must be exactly 32 bytes.")

    nonce = secrets.token_bytes(NONCE_SIZE)

    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(
        nonce,
        data,
        associated_data
    )

    return nonce, ciphertext


def decrypt_data(
    ciphertext: bytes,
    key: bytes,
    nonce: bytes,
    associated_data: bytes | None = None
) -> bytes:
    """Decrypt data using AES-256-GCM."""

    if len(key) != KEY_SIZE:
        raise ValueError("AES-256 key must be exactly 32 bytes.")

    if len(nonce) != NONCE_SIZE:
        raise ValueError("Nonce must be exactly 12 bytes.")

    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(
        nonce,
        ciphertext,
        associated_data
    )

    return plaintext


def encrypt_file(
    input_path: str,
    output_path: str,
    key: bytes
) -> None:
    """Encrypt a file using AES-256-GCM."""

    with open(input_path, "rb") as file:
        data = file.read()

    nonce, ciphertext = encrypt_data(data, key)

    with open(output_path, "wb") as file:
        file.write(nonce)
        file.write(ciphertext)


def decrypt_file(
    input_path: str,
    output_path: str,
    key: bytes
) -> None:
    """Decrypt an AES-256-GCM encrypted file."""

    with open(input_path, "rb") as file:
        encrypted_data = file.read()

    nonce = encrypted_data[:NONCE_SIZE]
    ciphertext = encrypted_data[NONCE_SIZE:]

    plaintext = decrypt_data(
        ciphertext,
        key,
        nonce
    )

    with open(output_path, "wb") as file:
        file.write(plaintext)