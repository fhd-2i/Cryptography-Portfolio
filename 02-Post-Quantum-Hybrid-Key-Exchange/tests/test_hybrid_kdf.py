import secrets

from app.hybrid_kdf import derive_hybrid_key


def test_same_inputs_produce_same_key():
    x_secret = secrets.token_bytes(32)
    pq_secret = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)

    key1 = derive_hybrid_key(
        x_secret,
        pq_secret,
        salt,
    )

    key2 = derive_hybrid_key(
        x_secret,
        pq_secret,
        salt,
    )

    assert key1 == key2


def test_different_x25519_secret_changes_key():
    x_secret_1 = secrets.token_bytes(32)
    x_secret_2 = secrets.token_bytes(32)
    pq_secret = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)

    key1 = derive_hybrid_key(
        x_secret_1,
        pq_secret,
        salt,
    )

    key2 = derive_hybrid_key(
        x_secret_2,
        pq_secret,
        salt,
    )

    assert key1 != key2


def test_different_mlkem_secret_changes_key():
    x_secret = secrets.token_bytes(32)
    pq_secret_1 = secrets.token_bytes(32)
    pq_secret_2 = secrets.token_bytes(32)
    salt = secrets.token_bytes(16)

    key1 = derive_hybrid_key(
        x_secret,
        pq_secret_1,
        salt,
    )

    key2 = derive_hybrid_key(
        x_secret,
        pq_secret_2,
        salt,
    )

    assert key1 != key2


def test_different_salt_changes_key():
    x_secret = secrets.token_bytes(32)
    pq_secret = secrets.token_bytes(32)

    key1 = derive_hybrid_key(
        x_secret,
        pq_secret,
        secrets.token_bytes(16),
    )

    key2 = derive_hybrid_key(
        x_secret,
        pq_secret,
        secrets.token_bytes(16),
    )

    assert key1 != key2


def test_derived_key_is_256_bits():
    key = derive_hybrid_key(
        secrets.token_bytes(32),
        secrets.token_bytes(32),
        secrets.token_bytes(16),
    )

    assert len(key) == 32


def test_invalid_salt_length_rejected():
    try:
        derive_hybrid_key(
            secrets.token_bytes(32),
            secrets.token_bytes(32),
            b"short",
        )
    except ValueError:
        return

    assert False