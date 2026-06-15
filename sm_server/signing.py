"""did:key derivation + Ed25519 verification — the crypto the protocol surface needs.

Same primitives as the conformance suite and sm-conformance: W3C did:key
(multibase base58btc over multicodec 0xed01 ‖ pubkey32) and Ed25519 over a
canonical string. No backend, no framework — pure functions.
"""

from __future__ import annotations

import base58
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ED25519_MULTICODEC_PREFIX = b"\xed\x01"

_RAW = serialization.Encoding.Raw
_RAW_PUB = serialization.PublicFormat.Raw


def generate_chapter_identity() -> tuple[Ed25519PrivateKey, bytes, str]:
    """Return (private_key, pubkey32, did_key) for the server's own identity."""
    priv = Ed25519PrivateKey.generate()
    pub32 = priv.public_key().public_bytes(_RAW, _RAW_PUB)
    return priv, pub32, derive_did_key(pub32)


def derive_did_key(pubkey32: bytes) -> str:
    if len(pubkey32) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(pubkey32)}")
    return "did:key:z" + base58.b58encode(ED25519_MULTICODEC_PREFIX + pubkey32).decode("ascii")


def parse_did_key(did_key: str) -> bytes:
    if not did_key.startswith("did:key:z"):
        raise ValueError(f"not a did:key: {did_key!r}")
    decoded = base58.b58decode(did_key[len("did:key:z") :])
    if not decoded.startswith(ED25519_MULTICODEC_PREFIX):
        raise ValueError("did:key does not encode an Ed25519 key")
    pub = decoded[len(ED25519_MULTICODEC_PREFIX) :]
    if len(pub) != 32:
        raise ValueError(f"decoded key has wrong length: {len(pub)}")
    return pub


def verify(pubkey32: bytes, signature: bytes, message: bytes) -> bool:
    """True iff `signature` is a valid Ed25519 signature over `message` by `pubkey32`."""
    try:
        Ed25519PublicKey.from_public_bytes(pubkey32).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False
