import base64
import json
from pathlib import Path

from app.hybrid_kex import HybridKeyExchange


KEYS_DIR = Path("keys")
PUBLIC_KEY_FILE = KEYS_DIR / "recipient_public.json"
PRIVATE_KEY_FILE = KEYS_DIR / "recipient_private.json"


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


def create_recipient_identity() -> None:
    hybrid = HybridKeyExchange()

    KEYS_DIR.mkdir(exist_ok=True)

    x_private, x_public = hybrid.generate_x25519_keypair()
    mlkem_public, mlkem_private = hybrid.generate_mlkem_keypair()

    public_data = {
        "version": 1,
        "x25519_public": _b64encode(x_public),
        "mlkem_public": _b64encode(mlkem_public),
    }

    private_data = {
        "version": 1,
        "x25519_private": _b64encode(x_private),
        "mlkem_private": _b64encode(mlkem_private),
    }

    PUBLIC_KEY_FILE.write_text(
        json.dumps(public_data, indent=4),
        encoding="utf-8",
    )

    PRIVATE_KEY_FILE.write_text(
        json.dumps(private_data, indent=4),
        encoding="utf-8",
    )


def load_public_identity() -> tuple[bytes, bytes]:
    if not PUBLIC_KEY_FILE.exists():
        raise FileNotFoundError(
            "Recipient public identity not found. Run init first."
        )

    data = json.loads(
        PUBLIC_KEY_FILE.read_text(encoding="utf-8")
    )

    return (
        _b64decode(data["x25519_public"]),
        _b64decode(data["mlkem_public"]),
    )


def load_private_identity() -> tuple[bytes, bytes]:
    if not PRIVATE_KEY_FILE.exists():
        raise FileNotFoundError(
            "Recipient private identity not found. Run init first."
        )

    data = json.loads(
        PRIVATE_KEY_FILE.read_text(encoding="utf-8")
    )

    return (
        _b64decode(data["x25519_private"]),
        _b64decode(data["mlkem_private"]),
    )