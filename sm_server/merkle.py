"""RFC 6962 Merkle tree + a signed checkpoint over the ARP Issuer Log.

The per-issuer hash chain (ARP §6.4) gives *forward* tamper-evidence inside one
issuer's receipts. This adds the *reverse* seam across the whole log: the server
signs a checkpoint anchoring an RFC 6962 Merkle tree over every receipt it holds,
and any holder of a receipt + its inclusion proof + the signed root can verify
membership offline — without the rest of the log, and without trusting the
server's say-so.

Pure functions over raw leaf bytes; domain-separated leaf/node hashes per
RFC 6962 §2.1. The leaf is the JCS-canonical bytes of the full signed receipt,
so the checkpoint commits to the exact receipt a verifier reconstructs.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from sm_arp import Identity, canonical_bytes, now_iso

CHECKPOINT_VERSION = "aae-checkpoint/0.1"


# ── RFC 6962 §2.1: domain-separated hashes ──────────────────────────────


def _leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_pow2_lt(n: int) -> int:
    """Largest power of two strictly less than n (n > 1)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves: list[bytes]) -> bytes:
    """RFC 6962 Merkle Tree Hash over raw leaf data."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return _leaf_hash(leaves[0])
    k = _largest_pow2_lt(n)
    return _node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def inclusion_proof(leaves: list[bytes], m: int) -> list[bytes]:
    """RFC 6962 audit path for leaf index ``m`` in the tree over ``leaves``."""
    n = len(leaves)
    if not 0 <= m < n:
        raise IndexError(f"leaf index {m} out of range for size {n}")
    if n == 1:
        return []
    k = _largest_pow2_lt(n)
    if m < k:
        return inclusion_proof(leaves[:k], m) + [merkle_root(leaves[k:])]
    return inclusion_proof(leaves[k:], m - k) + [merkle_root(leaves[:k])]


def verify_inclusion(
    *, leaf: bytes, leaf_index: int, tree_size: int, proof: list[bytes], root: bytes
) -> bool:
    """RFC 6962 inclusion-proof verification (the Trillian reference algorithm)."""
    if leaf_index >= tree_size:
        return False
    fn, sn = leaf_index, tree_size - 1
    r = _leaf_hash(leaf)
    for p in proof:
        if fn == sn or (fn & 1):
            r = _node_hash(p, r)
            while fn != 0 and (fn & 1) == 0:
                fn >>= 1
                sn >>= 1
        else:
            r = _node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


# ── Checkpoint envelope (aae-checkpoint/0.1) ────────────────────────────


def checkpoint_leaves(receipts: list[dict[str, Any]]) -> list[bytes]:
    """Canonical leaf bytes — JCS over the FULL receipt (including signature).

    Receipts MUST be passed in the committed order; the checkpoint root and
    every inclusion proof are taken over this same ordered leaf list.
    """
    return [canonical_bytes(r, include_signature=True) for r in receipts]


def build_checkpoint(receipts: list[dict[str, Any]], *, identity: Identity) -> dict[str, Any]:
    """Sign an RFC 6962 Merkle checkpoint committing to ``receipts`` in order.

    The payload is signed over its JCS-canonical bytes by ``identity`` (the
    server's own ARP key). ``canonical_bytes(payload, include_signature=True)``
    is exactly ``jcs.canonicalize(payload)`` here because the payload carries no
    ``signature`` field — so the signed bytes match the cross-runtime format.
    """
    root = merkle_root(checkpoint_leaves(receipts))
    payload: dict[str, Any] = {
        "version": CHECKPOINT_VERSION,
        "type": "checkpoint",
        "signer_did": identity.did,
        "created_at": now_iso(),
        "tree_size": len(receipts),
        "merkle_root": "sha256:" + root.hex(),
        "receipt_ids": [r["receipt_id"] for r in receipts],
    }
    sig = identity.sign(canonical_bytes(payload, include_signature=True))
    return {
        "payload": payload,
        "signer_did": identity.did,
        "signature": base64.b64encode(sig).decode("ascii"),
    }
