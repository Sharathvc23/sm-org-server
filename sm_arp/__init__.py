"""sm-arp — the Agency Receipt Protocol, as a consumable library.

One canonical implementation of building, signing, and verifying ARP v0.1
receipts, plus a SQLite receipt log. Every runtime imports this rather than
vendoring its own copy, so the receipt envelope cannot drift between an issuer
(server side / Issuer Log) and a principal's agent (client side / Agency Log)
— drift is exactly what the conformance suite exists to catch.

    from sm_arp import Identity, build_action, issue_receipt, verify_receipt, IssuerLog

    me = Identity.generate()
    r = issue_receipt(me, principal_did=me.did,
                      action=build_action(category="data_shared", human_summary="…"))
    assert verify_receipt(r).ok
    IssuerLog("log.sqlite").append(r)
"""

from __future__ import annotations

from .identity import Identity, did_from_sk, gen_key, pubkey_from_did
from .receipts import (
    ARP_VERSION,
    KNOWN_CATEGORIES,
    OUTCOMES,
    VerifyResult,
    build_action,
    canonical_bytes,
    chain_link,
    issue_receipt,
    new_receipt_id,
    now_iso,
    verify_authority_chain,
    verify_hash_chain,
    verify_receipt,
    verify_signature,
)
from .store import AgencyLog, IssuerLog, ReceiptLog

__all__ = [
    "ARP_VERSION",
    "KNOWN_CATEGORIES",
    "OUTCOMES",
    "AgencyLog",
    "Identity",
    "IssuerLog",
    "ReceiptLog",
    "VerifyResult",
    "build_action",
    "canonical_bytes",
    "chain_link",
    "did_from_sk",
    "gen_key",
    "issue_receipt",
    "new_receipt_id",
    "now_iso",
    "pubkey_from_did",
    "verify_authority_chain",
    "verify_hash_chain",
    "verify_receipt",
    "verify_signature",
]
