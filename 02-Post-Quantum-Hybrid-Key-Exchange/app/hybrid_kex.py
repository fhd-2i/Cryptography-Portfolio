from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from mlkem.ml_kem import ML_KEM
from mlkem.parameter_set import ML_KEM_768


class HybridKeyExchange:
    def __init__(self) -> None:
        self.kem = ML_KEM(ML_KEM_768, fast=False)

    @staticmethod
    def generate_x25519_keypair() -> tuple[bytes, bytes]:
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        return private_bytes, public_bytes

    @staticmethod
    def x25519_shared_secret(
        private_key_bytes: bytes,
        peer_public_key_bytes: bytes,
    ) -> bytes:
        private_key = X25519PrivateKey.from_private_bytes(private_key_bytes)
        peer_public_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)

        return private_key.exchange(peer_public_key)

    def generate_mlkem_keypair(self) -> tuple[bytes, bytes]:
        encapsulation_key, decapsulation_key = self.kem.key_gen()

        return encapsulation_key, decapsulation_key

    def mlkem_encapsulate(
        self,
        encapsulation_key: bytes,
    ) -> tuple[bytes, bytes]:
        shared_secret, ciphertext = self.kem.encaps(encapsulation_key)

        return shared_secret, ciphertext

    def mlkem_decapsulate(
        self,
        decapsulation_key: bytes,
        ciphertext: bytes,
    ) -> bytes:
        return self.kem.decaps(
            decapsulation_key,
            ciphertext,
        )