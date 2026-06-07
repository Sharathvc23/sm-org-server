"""ARP v0.1 receipts — build, sign, and verify per ``spec/arp/0.1``.

* canonicalise the body sans-``signature`` with RFC 8785 JCS,
* sign the canonical bytes with the issuer's Ed25519 key,
* attach a standard-base64 (padded) signature.

Verification resolves ``issuer_did`` to a public key via did:key and checks the
structural envelope, the signature, the optional ``previous_receipt_hash`` chain
(§6.4), and the optional ``authority_chain`` back to a grant (§4.5).
"""

from __future__ import annotations

import base64
import hashlib
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import jcs
from cryptography.exceptions import InvalidSignature

from .identity import Identity, pubkey_from_did

ARP_VERSION = "arp/0.1"

_UUID_V4_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_RFC3339_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

KNOWN_CATEGORIES = {
    "purchase", "payment_sent", "payment_received", "message_sent",
    "message_received", "decision_made", "data_shared", "appointment_booked",
    "appointment_cancelled", "subscription_changed", "record_filed",
    "account_created", "account_closed", "attestation_issued",
    "attestation_received", "vote_cast", "authority_granted",
    "authority_revoked", "other",
}  # fmt: skip
OUTCOMES = {"completed", "failed", "partial", "reversed", "pending"}


def new_receipt_id() -> str:
    return str(uuid.uuid4())


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_bytes(receipt: dict[str, Any], *, include_signature: bool) -> bytes:
    """JCS-canonical bytes of a receipt, with or without the signature field."""
    body = {k: v for k, v in receipt.items() if include_signature or k != "signature"}
    return jcs.canonicalize(body)


def chain_link(receipt: dict[str, Any]) -> str:
    """``sha256:<hex>`` over the JCS bytes of a *signed* receipt (§6.4)."""
    digest = hashlib.sha256(canonical_bytes(receipt, include_signature=True)).hexdigest()
    return f"sha256:{digest}"


def build_action(
    *,
    category: str,
    human_summary: str,
    outcome: str = "completed",
    counterparty_did: str | None = None,
    counterparty_label: str | None = None,
    amount_cents: int | None = None,
    currency: str = "USD",
    granted_by_receipt_id: str | None = None,
    machine_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    action: dict[str, Any] = {
        "category": category,
        "human_summary": human_summary,
        "outcome": outcome,
    }
    if counterparty_did:
        action["counterparty_did"] = counterparty_did
    if counterparty_label:
        action["counterparty_label"] = counterparty_label
    if amount_cents is not None:
        action["amount"] = {"currency": currency, "cents": amount_cents}
    if granted_by_receipt_id:
        action["granted_by_receipt_id"] = granted_by_receipt_id
    if machine_payload is not None:
        action["machine_payload"] = machine_payload
    return action


def issue_receipt(
    issuer: Identity,
    *,
    principal_did: str,
    action: dict[str, Any],
    authority_chain: list[str] | None = None,
    evidence: dict[str, Any] | None = None,
    previous_receipt_hash: str | None = None,
    receipt_id: str | None = None,
    issued_at: str | None = None,
    composition: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble and sign an ARP receipt with ``issuer``'s key."""
    rid = receipt_id or new_receipt_id()
    iso = issued_at or now_iso()
    if not _UUID_V4_RE.match(rid):
        raise ValueError(f"receipt_id {rid!r} is not a canonical UUIDv4")
    if not _RFC3339_UTC_RE.match(iso):
        raise ValueError(f"issued_at {iso!r} must be RFC 3339 UTC second precision")

    receipt: dict[str, Any] = {
        "version": ARP_VERSION,
        "receipt_id": rid,
        "issuer_did": issuer.did,
        "principal_did": principal_did,
        "issued_at": iso,
        "action": action,
    }
    if authority_chain:
        receipt["authority_chain"] = authority_chain
    if evidence:
        receipt["evidence"] = evidence
    if composition:
        receipt["composition"] = composition
    if previous_receipt_hash:
        receipt["previous_receipt_hash"] = previous_receipt_hash

    sig = issuer.sign(canonical_bytes(receipt, include_signature=False))
    receipt["signature"] = base64.b64encode(sig).decode("ascii")
    return receipt


@dataclass
class VerifyResult:
    ok: bool
    stage: str  # structure | signature | authority_chain | hash_chain | accepted
    detail: str

    @classmethod
    def accepted(cls) -> VerifyResult:
        return cls(True, "accepted", "receipt verifies")


_REQUIRED_TOP = ("version", "receipt_id", "issuer_did", "principal_did", "issued_at", "action", "signature")


def _check_structure(r: dict[str, Any], *, strict: bool) -> VerifyResult | None:
    if not isinstance(r, dict):
        return VerifyResult(False, "structure", "receipt is not an object")
    for field in _REQUIRED_TOP:
        if field not in r:
            return VerifyResult(False, "structure", f"missing required field {field!r}")
    if r["version"] != ARP_VERSION:
        return VerifyResult(False, "structure", f"unexpected version {r['version']!r}")
    action = r["action"]
    for field in ("category", "human_summary", "outcome"):
        if field not in action:
            return VerifyResult(False, "structure", f"action missing {field!r}")
    if len(action["human_summary"]) > 280:
        return VerifyResult(False, "structure", "human_summary exceeds 280 code points")
    if action["outcome"] not in OUTCOMES:
        return VerifyResult(False, "structure", f"bad outcome {action['outcome']!r}")
    if strict and action["category"] not in KNOWN_CATEGORIES:
        return VerifyResult(False, "structure", f"unknown category {action['category']!r}")
    return None


def verify_signature(r: dict[str, Any]) -> VerifyResult:
    """Resolve issuer_did and check the Ed25519 signature over canonical bytes."""
    try:
        pubkey = pubkey_from_did(r["issuer_did"])
    except Exception as e:  # noqa: BLE001
        return VerifyResult(False, "signature", f"unresolvable issuer_did: {e}")
    try:
        sig = base64.b64decode(r["signature"])
    except Exception as e:  # noqa: BLE001
        return VerifyResult(False, "signature", f"signature not base64: {e}")
    try:
        pubkey.verify(sig, canonical_bytes(r, include_signature=False))
    except InvalidSignature:
        return VerifyResult(False, "signature", "Ed25519 signature does not verify")
    return VerifyResult.accepted()


def verify_authority_chain(r: dict[str, Any], grants: dict[str, dict[str, Any]]) -> VerifyResult:
    """Strict §4.5 check of ``action.granted_by_receipt_id`` against a grant index."""
    gid = r["action"].get("granted_by_receipt_id")
    if not gid:
        return VerifyResult.accepted()  # standing authority; nothing to check
    grant = grants.get(gid)
    if grant is None:
        return VerifyResult(False, "authority_chain", f"grant {gid} not found")
    if grant["principal_did"] != r["principal_did"]:
        return VerifyResult(False, "authority_chain", "principal mismatch with grant")
    if grant["action"]["category"] != "authority_granted":
        return VerifyResult(False, "authority_chain", f"{gid} is not an authority_granted receipt")
    mp = grant["action"].get("machine_payload", {})
    expires = mp.get("grant_expires_at", "")
    if expires and expires <= r["issued_at"]:
        return VerifyResult(False, "authority_chain", f"grant expired ({expires})")
    scope = mp.get("granted_scope", [])
    cat = r["action"]["category"]
    if cat not in scope and "*" not in scope:
        return VerifyResult(False, "authority_chain", f"category {cat!r} outside grant scope {scope}")
    if mp.get("granted_to_did") not in (None, r["issuer_did"]):
        return VerifyResult(False, "authority_chain", "issuer is not the grantee")
    return VerifyResult.accepted()


def verify_hash_chain(r: dict[str, Any], prior: dict[str, Any] | None) -> VerifyResult:
    """Check the per-issuer hash chain link (§6.4)."""
    declared = r.get("previous_receipt_hash")
    if prior is None:
        if declared:
            return VerifyResult(False, "hash_chain", "genesis receipt declares a previous_receipt_hash")
        return VerifyResult.accepted()
    if not declared:
        return VerifyResult(False, "hash_chain", "missing previous_receipt_hash on a non-genesis receipt")
    if declared != chain_link(prior):
        return VerifyResult(False, "hash_chain", "previous_receipt_hash does not match predecessor")
    return VerifyResult.accepted()


def verify_receipt(
    r: dict[str, Any],
    *,
    mode: str = "strict",
    grants: dict[str, dict[str, Any]] | None = None,
    prior: dict[str, Any] | None = None,
    check_chain: bool = False,
) -> VerifyResult:
    """Full verification: structure → signature → authority → hash chain."""
    strict = mode == "strict"
    structural = _check_structure(r, strict=strict)
    if structural is not None:
        return structural
    sig = verify_signature(r)
    if not sig.ok:
        return sig
    if grants is not None:
        chain = verify_authority_chain(r, grants)
        if not chain.ok:
            return chain
    if check_chain:
        hc = verify_hash_chain(r, prior)
        if not hc.ok:
            return hc
    return VerifyResult.accepted()
