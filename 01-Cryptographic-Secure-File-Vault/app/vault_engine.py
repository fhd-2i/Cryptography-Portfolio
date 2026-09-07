from pathlib import Path
import hashlib
import secrets
import string

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from app.aes import (
    generate_key,
    encrypt_data,
    decrypt_data,
)

from app.ecc import (
    derive_shared_secret,
    serialize_public_key,
)

from app.hashing import derive_key

from app.key_management import (
    wrap_key,
    unwrap_key,
)

from app.signatures import (
    sign_data,
    verify_signature,
)

from app.vault_format import (
    VaultPackage,
    canonicalize_package,
    encode_vault,
    decode_vault,
)


SALT_SIZE = 16
NONCE_SIZE = 12
PUBLIC_KEY_SIZE = 32
SIGNATURE_SIZE = 64
WRAPPED_KEY_SIZE = 48
MIN_CIPHERTEXT_SIZE = 16
FILE_HASH_LENGTH = 64

HKDF_INFO = (
    b"cryptographic-secure-vault-file-key-v1"
)


def calculate_file_hash(
    data: bytes,
) -> str:
    """Calculate the SHA-256 fingerprint of file data."""

    return hashlib.sha256(
        data
    ).hexdigest()


def validate_package(
    package: VaultPackage,
) -> None:
    """
    Validate the structure and cryptographic
    parameters of a vault package before decryption.
    """

    if package.version != 1:
        raise ValueError(
            "Unsupported vault version."
        )

    if package.encryption != "AES-256-GCM":
        raise ValueError(
            "Unsupported encryption algorithm."
        )

    if package.key_exchange != "X25519":
        raise ValueError(
            "Unsupported key exchange algorithm."
        )

    if package.kdf != "HKDF-SHA256":
        raise ValueError(
            "Unsupported key derivation function."
        )

    if len(package.salt) != SALT_SIZE:
        raise ValueError(
            "Invalid vault salt."
        )

    if len(package.ephemeral_public_key) != PUBLIC_KEY_SIZE:
        raise ValueError(
            "Invalid ephemeral X25519 public key."
        )

    if len(package.file_nonce) != NONCE_SIZE:
        raise ValueError(
            "Invalid file nonce."
        )

    if len(package.wrapped_key_nonce) != NONCE_SIZE:
        raise ValueError(
            "Invalid wrapped-key nonce."
        )

    if len(package.wrapped_file_key) != WRAPPED_KEY_SIZE:
        raise ValueError(
            "Invalid wrapped file key."
        )

    if len(package.signing_public_key) != PUBLIC_KEY_SIZE:
        raise ValueError(
            "Invalid Ed25519 public key."
        )

    if len(package.signature) != SIGNATURE_SIZE:
        raise ValueError(
            "Invalid Ed25519 signature."
        )

    if len(package.ciphertext) < MIN_CIPHERTEXT_SIZE:
        raise ValueError(
            "Invalid ciphertext."
        )

    if not isinstance(
        package.file_hash,
        str,
    ):
        raise ValueError(
            "Invalid file hash."
        )

    if len(package.file_hash) != FILE_HASH_LENGTH:
        raise ValueError(
            "Invalid file hash length."
        )

    if any(
        character not in string.hexdigits
        for character in package.file_hash
    ):
        raise ValueError(
            "Invalid SHA-256 file hash."
        )

    if not isinstance(
        package.filename,
        str,
    ):
        raise ValueError(
            "Invalid filename."
        )

    if not package.filename:
        raise ValueError(
            "Invalid filename."
        )


def create_vault(
    input_path: str,
    output_path: str,
    recipient_public_key: X25519PublicKey,
    signing_private_key: Ed25519PrivateKey,
) -> None:
    """Encrypt a file into a cryptographic vault."""

    input_file = Path(
        input_path
    )

    output_file = Path(
        output_path
    )

    if not input_file.exists():
        raise FileNotFoundError(
            f"Input file not found: {input_path}"
        )

    if not input_file.is_file():
        raise ValueError(
            f"Input path is not a regular file: {input_path}"
        )

    if output_file.exists():
        raise FileExistsError(
            f"Output file already exists: {output_path}"
        )

    plaintext = input_file.read_bytes()

    if not plaintext:
        raise ValueError(
            "Input file is empty."
        )

    file_encryption_key = generate_key()

    file_nonce, ciphertext = encrypt_data(
        plaintext,
        file_encryption_key,
    )

    ephemeral_private_key = (
        X25519PrivateKey.generate()
    )

    ephemeral_public_key = (
        ephemeral_private_key.public_key()
    )

    shared_secret = derive_shared_secret(
        ephemeral_private_key,
        recipient_public_key,
    )

    salt = secrets.token_bytes(
        SALT_SIZE
    )

    key_encryption_key = derive_key(
        shared_secret,
        salt=salt,
        info=HKDF_INFO,
    )

    wrapped_key_nonce, wrapped_file_key = wrap_key(
        file_encryption_key,
        key_encryption_key,
    )

    file_hash = calculate_file_hash(
        plaintext
    )

    signing_public_key = (
        signing_private_key
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )

    package = VaultPackage(
        version=1,
        encryption="AES-256-GCM",
        key_exchange="X25519",
        kdf="HKDF-SHA256",
        salt=salt,
        ephemeral_public_key=serialize_public_key(
            ephemeral_public_key
        ),
        file_nonce=file_nonce,
        wrapped_key_nonce=wrapped_key_nonce,
        wrapped_file_key=wrapped_file_key,
        signing_public_key=signing_public_key,
        signature=b"",
        ciphertext=ciphertext,
        file_hash=file_hash,
        filename=input_file.name,
    )

    signed_data = canonicalize_package(
        package
    )

    signature = sign_data(
        signed_data,
        signing_private_key,
    )

    package.signature = signature

    output_file.write_bytes(
        encode_vault(package)
    )


def decrypt_vault(
    vault_path: str,
    output_path: str,
    recipient_private_key: X25519PrivateKey,
    trusted_signing_public_key: Ed25519PublicKey,
) -> None:
    """
    Decrypt and verify a cryptographic vault.

    The vault's embedded Ed25519 public key must match
    the trusted local public key before the signature
    is accepted.
    """

    vault_file = Path(
        vault_path
    )

    output_file = Path(
        output_path
    )

    if not vault_file.exists():
        raise FileNotFoundError(
            f"Vault file not found: {vault_path}"
        )

    if not vault_file.is_file():
        raise ValueError(
            f"Vault path is not a regular file: {vault_path}"
        )

    if output_file.exists():
        raise FileExistsError(
            f"Output file already exists: {output_path}"
        )

    vault_data = vault_file.read_bytes()

    if not vault_data:
        raise ValueError(
            "Vault file is empty."
        )

    try:
        package = decode_vault(
            vault_data
        )

    except ValueError:
        raise

    except Exception as exc:
        raise ValueError(
            "Invalid or corrupted vault format."
        ) from exc

    validate_package(
        package
    )

    vault_signing_public_key = (
        Ed25519PublicKey.from_public_bytes(
            package.signing_public_key
        )
    )

    trusted_public_bytes = (
        trusted_signing_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )

    vault_public_bytes = (
        package.signing_public_key
    )

    if vault_public_bytes != trusted_public_bytes:
        raise ValueError(
            "Vault signing key is not trusted."
        )

    signed_data = canonicalize_package(
        package
    )

    signature_valid = verify_signature(
        signed_data,
        package.signature,
        vault_signing_public_key,
    )

    if not signature_valid:
        raise ValueError(
            "Vault signature verification failed."
        )

    ephemeral_public_key = (
        X25519PublicKey.from_public_bytes(
            package.ephemeral_public_key
        )
    )

    shared_secret = derive_shared_secret(
        recipient_private_key,
        ephemeral_public_key,
    )

    key_encryption_key = derive_key(
        shared_secret,
        salt=package.salt,
        info=HKDF_INFO,
    )

    file_encryption_key = unwrap_key(
        package.wrapped_file_key,
        key_encryption_key,
        package.wrapped_key_nonce,
    )

    try:
        plaintext = decrypt_data(
            package.ciphertext,
            file_encryption_key,
            package.file_nonce,
        )

    except Exception as exc:
        raise ValueError(
            "File decryption failed."
        ) from exc

    calculated_hash = calculate_file_hash(
        plaintext
    )

    if calculated_hash != package.file_hash:
        raise ValueError(
            "File integrity verification failed."
        )

    output_file.write_bytes(
        plaintext
    )