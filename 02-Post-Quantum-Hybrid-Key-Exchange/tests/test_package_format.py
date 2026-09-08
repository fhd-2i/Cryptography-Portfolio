import json
import secrets

import pytest

from app.package_format import (
    create_package,
    deserialize_package,
    serialize_package,
)


def create_sample_package():
    return create_package(
        sender_x25519_public=secrets.token_bytes(32),
        mlkem_ciphertext=secrets.token_bytes(1088),
        salt=secrets.token_bytes(16),
        nonce=secrets.token_bytes(12),
        ciphertext=secrets.token_bytes(64),
    )


def test_package_roundtrip():
    original = create_sample_package()

    serialized = serialize_package(
        original
    )

    restored = deserialize_package(
        serialized
    )

    assert restored["version"] == 1
    assert len(restored["sender_x25519_public"]) == 32
    assert len(restored["salt"]) == 16
    assert len(restored["nonce"]) == 12


def test_invalid_json_rejected():
    with pytest.raises(ValueError):
        deserialize_package(
            "{invalid-json"
        )


def test_missing_field_rejected():
    package = create_sample_package()

    del package["nonce"]

    serialized = json.dumps(
        package
    )

    with pytest.raises(ValueError):
        deserialize_package(
            serialized
        )


def test_invalid_version_rejected():
    package = create_sample_package()

    package["version"] = 999

    serialized = json.dumps(
        package
    )

    with pytest.raises(ValueError):
        deserialize_package(
            serialized
        )


def test_invalid_base64_rejected():
    package = create_sample_package()

    package["ciphertext"] = "%%%INVALID%%%"

    serialized = json.dumps(
        package
    )

    with pytest.raises(ValueError):
        deserialize_package(
            serialized
        )