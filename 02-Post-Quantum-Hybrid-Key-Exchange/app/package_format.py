import base64
import json


VERSION = 1

ALGORITHMS = {
    "classical_kex": "X25519",
    "post_quantum_kem": "ML-KEM-768",
    "kdf": "HKDF-SHA256",
    "aead": "AES-256-GCM",
}


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(data: str) -> bytes:
    try:
        return base64.b64decode(
            data.encode("ascii"),
            validate=True,
        )
    except Exception as exc:
        raise ValueError(
            "Invalid Base64 encoded field."
        ) from exc


def create_package(
    sender_x25519_public: bytes,
    mlkem_ciphertext: bytes,
    salt: bytes,
    nonce: bytes,
    ciphertext: bytes,
) -> dict:
    return {
        "version": VERSION,
        "algorithms": ALGORITHMS,
        "sender_x25519_public": _b64encode(
            sender_x25519_public
        ),
        "mlkem_ciphertext": _b64encode(
            mlkem_ciphertext
        ),
        "salt": _b64encode(
            salt
        ),
        "nonce": _b64encode(
            nonce
        ),
        "ciphertext": _b64encode(
            ciphertext
        ),
    }


def serialize_package(package: dict) -> str:
    return json.dumps(
        package,
        indent=4,
    )


def deserialize_package(data: str) -> dict:
    try:
        package = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "Invalid JSON package."
        ) from exc

    required_fields = {
        "version",
        "algorithms",
        "sender_x25519_public",
        "mlkem_ciphertext",
        "salt",
        "nonce",
        "ciphertext",
    }

    missing = required_fields - package.keys()

    if missing:
        raise ValueError(
            f"Missing package fields: {sorted(missing)}"
        )

    if package["version"] != VERSION:
        raise ValueError(
            "Unsupported package version."
        )

    return {
        "version": package["version"],
        "algorithms": package["algorithms"],
        "sender_x25519_public": _b64decode(
            package["sender_x25519_public"]
        ),
        "mlkem_ciphertext": _b64decode(
            package["mlkem_ciphertext"]
        ),
        "salt": _b64decode(
            package["salt"]
        ),
        "nonce": _b64decode(
            package["nonce"]
        ),
        "ciphertext": _b64decode(
            package["ciphertext"]
        ),
    }