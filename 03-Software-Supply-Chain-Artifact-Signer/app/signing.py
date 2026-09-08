from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate_keypair(
    private_key_path: Path,
    public_key_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_key_path.write_bytes(private_bytes)
    public_key_path.write_bytes(public_bytes)


def sign_file(
    file_path: Path,
    private_key_path: Path,
) -> bytes:
    if not file_path.exists():
        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    private_key = serialization.load_pem_private_key(
        private_key_path.read_bytes(),
        password=None,
    )

    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError(
            "Private key is not an Ed25519 key."
        )

    data = file_path.read_bytes()

    return private_key.sign(data)


def verify_file(
    file_path: Path,
    signature: bytes,
    public_key_path: Path,
) -> bool:
    public_key = serialization.load_pem_public_key(
        public_key_path.read_bytes()
    )

    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError(
            "Public key is not an Ed25519 key."
        )

    data = file_path.read_bytes()

    try:
        public_key.verify(
            signature,
            data,
        )

        return True

    except InvalidSignature:
        return False