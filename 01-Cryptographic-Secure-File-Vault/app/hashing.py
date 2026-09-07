from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


KEY_SIZE = 32


def derive_key(
    shared_secret: bytes,
    salt: bytes | None = None,
    info: bytes = b"cryptographic-secure-vault"
) -> bytes:
    """Derive a 256-bit encryption key from a shared secret using HKDF."""

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        info=info,
    )

    return hkdf.derive(shared_secret)