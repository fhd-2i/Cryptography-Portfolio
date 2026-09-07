import base64
import binascii
import json
from dataclasses import dataclass


@dataclass
class VaultPackage:
    version: int
    encryption: str
    key_exchange: str
    kdf: str
    salt: bytes
    ephemeral_public_key: bytes
    file_nonce: bytes
    wrapped_key_nonce: bytes
    wrapped_file_key: bytes
    signing_public_key: bytes
    signature: bytes
    ciphertext: bytes
    file_hash: str
    filename: str


REQUIRED_FIELDS = {
    "version",
    "encryption",
    "key_exchange",
    "kdf",
    "salt",
    "ephemeral_public_key",
    "file_nonce",
    "wrapped_key_nonce",
    "wrapped_file_key",
    "signing_public_key",
    "signature",
    "ciphertext",
    "file_hash",
    "filename",
}


def _encode_bytes(data: bytes) -> str:
    """Encode binary data as Base64."""

    if not isinstance(data, bytes):
        raise TypeError(
            "Only bytes can be Base64 encoded."
        )

    return base64.b64encode(
        data
    ).decode("ascii")


def _decode_bytes(data: str) -> bytes:
    """Decode Base64 data using strict validation."""

    if not isinstance(data, str):
        raise ValueError(
            "Encoded binary field must be a string."
        )

    try:
        return base64.b64decode(
            data.encode("ascii"),
            validate=True,
        )

    except (
        ValueError,
        UnicodeEncodeError,
        binascii.Error,
    ) as exc:
        raise ValueError(
            "Invalid Base64 encoded field."
        ) from exc


def package_to_dict(
    package: VaultPackage,
    include_signature: bool = True,
) -> dict:
    """Convert a VaultPackage into a JSON-compatible dictionary."""

    data = {
        "version": package.version,
        "encryption": package.encryption,
        "key_exchange": package.key_exchange,
        "kdf": package.kdf,
        "salt": _encode_bytes(package.salt),
        "ephemeral_public_key": _encode_bytes(
            package.ephemeral_public_key
        ),
        "file_nonce": _encode_bytes(
            package.file_nonce
        ),
        "wrapped_key_nonce": _encode_bytes(
            package.wrapped_key_nonce
        ),
        "wrapped_file_key": _encode_bytes(
            package.wrapped_file_key
        ),
        "signing_public_key": _encode_bytes(
            package.signing_public_key
        ),
        "ciphertext": _encode_bytes(
            package.ciphertext
        ),
        "file_hash": package.file_hash,
        "filename": package.filename,
    }

    if include_signature:
        data["signature"] = _encode_bytes(
            package.signature
        )

    return data


def canonicalize_package(
    package: VaultPackage,
) -> bytes:
    """
    Create deterministic bytes for digital signature verification.

    The signature field is intentionally excluded.
    """

    data = package_to_dict(
        package,
        include_signature=False,
    )

    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def encode_vault(
    package: VaultPackage,
) -> bytes:
    """Serialize a VaultPackage into canonical JSON bytes."""

    data = package_to_dict(
        package,
        include_signature=True,
    )

    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def decode_vault(
    data: bytes,
) -> VaultPackage:
    """
    Decode and validate the basic JSON structure
    of a vault package.
    """

    if not isinstance(data, bytes):
        raise TypeError(
            "Vault data must be bytes."
        )

    if not data:
        raise ValueError(
            "Vault data cannot be empty."
        )

    try:
        parsed = json.loads(
            data.decode("utf-8")
        )

    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise ValueError(
            "Vault does not contain valid JSON."
        ) from exc

    if not isinstance(parsed, dict):
        raise ValueError(
            "Vault JSON root must be an object."
        )

    missing_fields = (
        REQUIRED_FIELDS - parsed.keys()
    )

    if missing_fields:
        missing = ", ".join(
            sorted(missing_fields)
        )

        raise ValueError(
            f"Vault is missing required fields: {missing}"
        )

    if not isinstance(
        parsed["version"],
        int,
    ) or isinstance(
        parsed["version"],
        bool,
    ):
        raise ValueError(
            "Vault version must be an integer."
        )

    string_fields = {
        "encryption",
        "key_exchange",
        "kdf",
        "file_hash",
        "filename",
    }

    for field in string_fields:
        if not isinstance(
            parsed[field],
            str,
        ):
            raise ValueError(
                f"Vault field '{field}' must be a string."
            )

    binary_fields = {
        "salt",
        "ephemeral_public_key",
        "file_nonce",
        "wrapped_key_nonce",
        "wrapped_file_key",
        "signing_public_key",
        "signature",
        "ciphertext",
    }

    decoded = {}

    for field in binary_fields:
        decoded[field] = _decode_bytes(
            parsed[field]
        )

    return VaultPackage(
        version=parsed["version"],
        encryption=parsed["encryption"],
        key_exchange=parsed["key_exchange"],
        kdf=parsed["kdf"],
        salt=decoded["salt"],
        ephemeral_public_key=decoded[
            "ephemeral_public_key"
        ],
        file_nonce=decoded["file_nonce"],
        wrapped_key_nonce=decoded[
            "wrapped_key_nonce"
        ],
        wrapped_file_key=decoded[
            "wrapped_file_key"
        ],
        signing_public_key=decoded[
            "signing_public_key"
        ],
        signature=decoded["signature"],
        ciphertext=decoded["ciphertext"],
        file_hash=parsed["file_hash"],
        filename=parsed["filename"],
    )