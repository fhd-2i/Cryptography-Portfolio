from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


HYBRID_KEY_SIZE = 32
HKDF_INFO = b"post-quantum-hybrid-key-exchange-v1"


def derive_hybrid_key(
    x25519_secret: bytes,
    mlkem_secret: bytes,
    salt: bytes,
) -> bytes:
    if not x25519_secret:
        raise ValueError("X25519 shared secret cannot be empty.")

    if not mlkem_secret:
        raise ValueError("ML-KEM shared secret cannot be empty.")

    if len(salt) != 16:
        raise ValueError("Salt must be exactly 16 bytes.")

    combined_secret = x25519_secret + mlkem_secret

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=HYBRID_KEY_SIZE,
        salt=salt,
        info=HKDF_INFO,
    )

    return hkdf.derive(combined_secret)