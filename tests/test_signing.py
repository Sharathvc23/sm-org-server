"""did:key derivation + Ed25519 verification."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sm_server import signing


def _raw_pub(priv: Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def test_did_key_round_trips() -> None:
    pub = _raw_pub(Ed25519PrivateKey.generate())
    did = signing.derive_did_key(pub)
    assert did.startswith("did:key:z")
    assert signing.parse_did_key(did) == pub


def test_derive_rejects_wrong_length() -> None:
    with pytest.raises(ValueError):
        signing.derive_did_key(b"\x00" * 31)


@pytest.mark.parametrize("bad", ["", "did:web:example.com", "did:key:QzNotMultibase"])
def test_parse_rejects_non_did_key(bad: str) -> None:
    with pytest.raises(ValueError):
        signing.parse_did_key(bad)


def test_verify_accepts_valid_and_rejects_tampered() -> None:
    priv = Ed25519PrivateKey.generate()
    pub = _raw_pub(priv)
    msg = b"canonical:string:123"
    sig = priv.sign(msg)
    assert signing.verify(pub, sig, msg) is True
    assert signing.verify(pub, sig, msg + b"x") is False
    assert signing.verify(pub, b"\x00" * 64, msg) is False
    assert signing.verify(b"\x00" * 5, sig, msg) is False  # malformed key, no raise


def test_generate_chapter_identity_is_consistent() -> None:
    priv, pub32, did = signing.generate_chapter_identity()
    assert len(pub32) == 32
    assert signing.parse_did_key(did) == pub32
    assert signing.verify(pub32, priv.sign(b"x"), b"x") is True
