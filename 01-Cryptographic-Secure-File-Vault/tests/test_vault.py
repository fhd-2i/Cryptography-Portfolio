import json

import pytest

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from cryptography.hazmat.primitives import serialization

from app.identity import (
    initialize_identity,
    load_x25519_private_key,
    load_x25519_public_key,
    load_ed25519_private_key,
    load_ed25519_public_key,
)

from app.vault_engine import (
    create_vault,
    decrypt_vault,
)

from app.vault_format import (
    decode_vault,
    canonicalize_package,
    encode_vault,
)


PASSWORD = "TestPassword123!"


def setup_identity(tmp_path):
    """Create a temporary cryptographic identity for testing."""

    keys_directory = tmp_path / "keys"

    initialize_identity(
        PASSWORD,
        str(keys_directory),
    )

    return keys_directory


def create_test_vault(tmp_path):
    """
    Create a valid vault and return
    the important test paths and keys.
    """

    keys_directory = setup_identity(
        tmp_path
    )

    input_file = tmp_path / "secret.txt"
    vault_file = tmp_path / "secret.vault"
    output_file = tmp_path / "restored.txt"

    input_file.write_bytes(
        b"Confidential information"
    )

    x25519_public_key = (
        load_x25519_public_key(
            str(keys_directory)
        )
    )

    x25519_private_key = (
        load_x25519_private_key(
            PASSWORD,
            str(keys_directory),
        )
    )

    ed25519_private_key = (
        load_ed25519_private_key(
            PASSWORD,
            str(keys_directory),
        )
    )

    ed25519_public_key = (
        load_ed25519_public_key(
            str(keys_directory)
        )
    )

    create_vault(
        str(input_file),
        str(vault_file),
        x25519_public_key,
        ed25519_private_key,
    )

    return (
        keys_directory,
        vault_file,
        output_file,
        x25519_private_key,
        ed25519_public_key,
    )


def test_vault_round_trip(tmp_path):
    """Encrypted file must decrypt to the original file."""

    (
        _,
        vault_file,
        output_file,
        x25519_private_key,
        ed25519_public_key,
    ) = create_test_vault(
        tmp_path
    )

    original_data = (
        b"Confidential information"
    )

    decrypt_vault(
        str(vault_file),
        str(output_file),
        x25519_private_key,
        ed25519_public_key,
    )

    assert (
        output_file.read_bytes()
        == original_data
    )


def test_wrong_password_rejected(tmp_path):
    """Wrong password must not decrypt the protected private key."""

    keys_directory = setup_identity(
        tmp_path
    )

    with pytest.raises(Exception):
        load_x25519_private_key(
            "WrongPassword123!",
            str(keys_directory),
        )


def test_wrong_recipient_rejected(tmp_path):
    """A different X25519 private key must not decrypt the vault."""

    (
        _,
        vault_file,
        output_file,
        _,
        ed25519_public_key,
    ) = create_test_vault(
        tmp_path
    )

    wrong_private_key = (
        X25519PrivateKey.generate()
    )

    with pytest.raises(Exception):
        decrypt_vault(
            str(vault_file),
            str(output_file),
            wrong_private_key,
            ed25519_public_key,
        )


def test_tampered_vault_rejected(tmp_path):
    """Changing vault data must invalidate the signature."""

    (
        keys_directory,
        vault_file,
        output_file,
        _,
        ed25519_public_key,
    ) = create_test_vault(
        tmp_path
    )

    parsed = json.loads(
        vault_file.read_text()
    )

    ciphertext = parsed["ciphertext"]

    replacement = (
        "A"
        if ciphertext[0] != "A"
        else "B"
    )

    parsed["ciphertext"] = (
        replacement
        + ciphertext[1:]
    )

    vault_file.write_text(
        json.dumps(parsed)
    )

    with pytest.raises(
        ValueError,
        match="signature",
    ):
        decrypt_vault(
            str(vault_file),
            str(output_file),
            load_x25519_private_key(
                PASSWORD,
                str(keys_directory),
            ),
            ed25519_public_key,
        )


def test_invalid_version_rejected(tmp_path):
    """Unsupported vault versions must be rejected."""

    (
        keys_directory,
        vault_file,
        output_file,
        _,
        ed25519_public_key,
    ) = create_test_vault(
        tmp_path
    )

    parsed = json.loads(
        vault_file.read_text()
    )

    parsed["version"] = 999

    vault_file.write_text(
        json.dumps(parsed)
    )

    with pytest.raises(
        ValueError,
        match="version",
    ):
        decrypt_vault(
            str(vault_file),
            str(output_file),
            load_x25519_private_key(
                PASSWORD,
                str(keys_directory),
            ),
            ed25519_public_key,
        )


def test_invalid_ciphertext_rejected(tmp_path):
    """Ciphertext shorter than a GCM authentication tag must be rejected."""

    (
        keys_directory,
        vault_file,
        output_file,
        _,
        ed25519_public_key,
    ) = create_test_vault(
        tmp_path
    )

    parsed = json.loads(
        vault_file.read_text()
    )

    parsed["ciphertext"] = "YWJj"

    vault_file.write_text(
        json.dumps(parsed)
    )

    with pytest.raises(
        ValueError,
        match="ciphertext",
    ):
        decrypt_vault(
            str(vault_file),
            str(output_file),
            load_x25519_private_key(
                PASSWORD,
                str(keys_directory),
            ),
            ed25519_public_key,
        )


def test_invalid_hash_rejected(tmp_path):
    """Invalid SHA-256 hash format must be rejected."""

    (
        keys_directory,
        vault_file,
        output_file,
        _,
        ed25519_public_key,
    ) = create_test_vault(
        tmp_path
    )

    parsed = json.loads(
        vault_file.read_text()
    )

    parsed["file_hash"] = "invalid"

    vault_file.write_text(
        json.dumps(parsed)
    )

    with pytest.raises(
        ValueError,
        match="hash",
    ):
        decrypt_vault(
            str(vault_file),
            str(output_file),
            load_x25519_private_key(
                PASSWORD,
                str(keys_directory),
            ),
            ed25519_public_key,
        )


def test_missing_required_field_rejected(tmp_path):
    """A vault with a missing required field must be rejected."""

    (
        keys_directory,
        vault_file,
        output_file,
        _,
        ed25519_public_key,
    ) = create_test_vault(
        tmp_path
    )

    parsed = json.loads(
        vault_file.read_text()
    )

    del parsed["ciphertext"]

    vault_file.write_text(
        json.dumps(parsed)
    )

    with pytest.raises(
        ValueError,
        match="missing required fields",
    ):
        decrypt_vault(
            str(vault_file),
            str(output_file),
            load_x25519_private_key(
                PASSWORD,
                str(keys_directory),
            ),
            ed25519_public_key,
        )


def test_invalid_base64_rejected(tmp_path):
    """Invalid Base64 data must be rejected."""

    (
        keys_directory,
        vault_file,
        output_file,
        _,
        ed25519_public_key,
    ) = create_test_vault(
        tmp_path
    )

    parsed = json.loads(
        vault_file.read_text()
    )

    parsed["ciphertext"] = (
        "THIS_IS_NOT_VALID_BASE64!!!"
    )

    vault_file.write_text(
        json.dumps(parsed)
    )

    with pytest.raises(
        ValueError,
        match="Base64",
    ):
        decrypt_vault(
            str(vault_file),
            str(output_file),
            load_x25519_private_key(
                PASSWORD,
                str(keys_directory),
            ),
            ed25519_public_key,
        )


def test_untrusted_signing_key_rejected(tmp_path):
    """
    A vault signed with a different Ed25519 key
    must be rejected even if the signature itself is valid.
    """

    (
        keys_directory,
        vault_file,
        output_file,
        x25519_private_key,
        trusted_public_key,
    ) = create_test_vault(
        tmp_path
    )

    package = decode_vault(
        vault_file.read_bytes()
    )

    attacker_private_key = (
        Ed25519PrivateKey.generate()
    )

    attacker_public_key = (
        attacker_private_key
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )

    package.signing_public_key = (
        attacker_public_key
    )

    package.signature = b""

    signed_data = (
        canonicalize_package(package)
    )

    package.signature = (
        attacker_private_key.sign(
            signed_data
        )
    )

    vault_file.write_bytes(
        encode_vault(package)
    )

    with pytest.raises(
        ValueError,
        match="not trusted",
    ):
        decrypt_vault(
            str(vault_file),
            str(output_file),
            x25519_private_key,
            trusted_public_key,
        )


def test_empty_input_file_rejected(tmp_path):
    """Empty input files must be rejected."""

    keys_directory = setup_identity(
        tmp_path
    )

    input_file = (
        tmp_path / "empty.txt"
    )

    vault_file = (
        tmp_path / "empty.vault"
    )

    input_file.write_bytes(
        b""
    )

    x25519_public_key = (
        load_x25519_public_key(
            str(keys_directory)
        )
    )

    ed25519_private_key = (
        load_ed25519_private_key(
            PASSWORD,
            str(keys_directory),
        )
    )

    with pytest.raises(
        ValueError,
        match="empty",
    ):
        create_vault(
            str(input_file),
            str(vault_file),
            x25519_public_key,
            ed25519_private_key,
        )


def test_existing_output_file_rejected(tmp_path):
    """Existing output files must not be overwritten."""

    keys_directory = setup_identity(
        tmp_path
    )

    input_file = (
        tmp_path / "secret.txt"
    )

    vault_file = (
        tmp_path / "secret.vault"
    )

    input_file.write_bytes(
        b"Confidential information"
    )

    vault_file.write_bytes(
        b"existing data"
    )

    x25519_public_key = (
        load_x25519_public_key(
            str(keys_directory)
        )
    )

    ed25519_private_key = (
        load_ed25519_private_key(
            PASSWORD,
            str(keys_directory),
        )
    )

    with pytest.raises(
        FileExistsError,
        match="already exists",
    ):
        create_vault(
            str(input_file),
            str(vault_file),
            x25519_public_key,
            ed25519_private_key,
        )