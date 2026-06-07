"""Ed25519 sovereign identity + did:key — the signing primitive for ARP.

An ``Identity`` wraps a 32-byte Ed25519 seed. ``did`` is the W3C did:key
(base58btc over multicodec ``0xed01`` || pubkey). ``sign`` signs raw bytes.
"""

from __future__ import annotations

from dataclasses import dataclass

import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_PREFIX = b"\xed\x01"


def gen_key() -> bytes:
    """A fresh 32-byte Ed25519 private seed."""
    return Ed25519PrivateKey.generate().private_bytes_raw()


def did_from_sk(sk_bytes: bytes) -> str:
    pk = Ed25519PrivateKey.from_private_bytes(sk_bytes).public_key().public_bytes_raw()
    return "did:key:z" + base58.b58encode(_PREFIX + pk).decode()


def pubkey_from_did(did: str) -> Ed25519PublicKey:
    """Resolve a did:key to its Ed25519 public key (inverse of ``did_from_sk``)."""
    if not did.startswith("did:key:z"):
        raise ValueError(f"not a did:key: {did!r}")
    raw = base58.b58decode(did[len("did:key:z") :])
    if not raw.startswith(_PREFIX):
        raise ValueError("did:key does not encode an Ed25519 key")
    pk = raw[len(_PREFIX) :]
    if len(pk) != 32:
        raise ValueError(f"decoded key has wrong length: {len(pk)}")
    return Ed25519PublicKey.from_public_bytes(pk)


@dataclass
class Identity:
    """An Ed25519 signing identity backed by a 32-byte seed."""

    sk_bytes: bytes

    @classmethod
    def generate(cls) -> Identity:
        return cls(gen_key())

    @classmethod
    def from_seed(cls, sk_bytes: bytes) -> Identity:
        if len(sk_bytes) != 32:
            raise ValueError(f"Ed25519 seed must be 32 bytes, got {len(sk_bytes)}")
        return cls(sk_bytes)

    @property
    def did(self) -> str:
        return did_from_sk(self.sk_bytes)

    def sign(self, data: bytes) -> bytes:
        return Ed25519PrivateKey.from_private_bytes(self.sk_bytes).sign(data)
