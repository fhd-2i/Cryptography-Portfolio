from app.hybrid_kex import HybridKeyExchange


def test_x25519_shared_secret_matches():
    hybrid = HybridKeyExchange()

    alice_private, alice_public = (
        hybrid.generate_x25519_keypair()
    )

    bob_private, bob_public = (
        hybrid.generate_x25519_keypair()
    )

    alice_secret = hybrid.x25519_shared_secret(
        alice_private,
        bob_public,
    )

    bob_secret = hybrid.x25519_shared_secret(
        bob_private,
        alice_public,
    )

    assert alice_secret == bob_secret


def test_x25519_shared_secret_is_32_bytes():
    hybrid = HybridKeyExchange()

    alice_private, _ = (
        hybrid.generate_x25519_keypair()
    )

    _, bob_public = (
        hybrid.generate_x25519_keypair()
    )

    secret = hybrid.x25519_shared_secret(
        alice_private,
        bob_public,
    )

    assert len(secret) == 32


def test_mlkem_shared_secret_matches():
    hybrid = HybridKeyExchange()

    public_key, private_key = (
        hybrid.generate_mlkem_keypair()
    )

    sender_secret, ciphertext = (
        hybrid.mlkem_encapsulate(
            public_key
        )
    )

    recipient_secret = (
        hybrid.mlkem_decapsulate(
            private_key,
            ciphertext,
        )
    )

    assert sender_secret == recipient_secret


def test_mlkem_shared_secret_is_32_bytes():
    hybrid = HybridKeyExchange()

    public_key, _ = (
        hybrid.generate_mlkem_keypair()
    )

    secret, _ = hybrid.mlkem_encapsulate(
        public_key
    )

    assert len(secret) == 32