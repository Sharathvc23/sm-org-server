"""Signed RFC 6962 Merkle checkpoint over the ARP Issuer Log.

The receipt hash chain proves *forward* tamper-evidence within one issuer; the
checkpoint proves *membership across the whole log*: anyone holding a receipt,
its inclusion proof, and the signed root verifies it offline — no chapter trust.

Prosecution-grade:
- C-port:  the Merkle math is validated against independently-computed RFC 6962
           known answers (empty/1/2/3/4 leaves), so a subtly-wrong port that
           still passes its own happy path is caught.
- C2:      every accept path has a hostile twin (tampered receipt, tampered
           payload signature, out-of-range index).
- C5:      boundary proofs (empty log, single leaf, unknown receipt).
"""

from __future__ import annotations

import base64
import hashlib

import pytest
from fastapi.testclient import TestClient
from sm_arp import Identity, build_action, canonical_bytes, issue_receipt

from sm_server import merkle, signing
from sm_server.app import create_app
from sm_server.store.sqlite import SqliteStore


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(store=SqliteStore(), chapter_id="test-chapter"))


def _ingest(client: TestClient, n: int) -> list[dict]:
    """Mint and ingest ``n`` independent signed receipts; return them."""
    receipts = []
    for i in range(n):
        issuer = Identity.generate()
        r = issue_receipt(
            issuer,
            principal_did=issuer.did,
            action=build_action(category="data_shared", human_summary=f"event {i}"),
        )
        assert client.post("/api/receipts", json=r).status_code == 200
        receipts.append(r)
    return receipts


def _unhex(s: str) -> bytes:
    return bytes.fromhex(s.removeprefix("sha256:"))


# ── C-port: RFC 6962 known answers (independent recomputation) ──────────


def test_merkle_root_matches_rfc6962_known_answers() -> None:
    def lh(d: bytes) -> bytes:
        return hashlib.sha256(b"\x00" + d).digest()

    def nh(a: bytes, b: bytes) -> bytes:
        return hashlib.sha256(b"\x01" + a + b).digest()

    assert merkle.merkle_root([]) == hashlib.sha256(b"").digest()
    assert merkle.merkle_root([b"d0"]) == lh(b"d0")
    assert merkle.merkle_root([b"d0", b"d1"]) == nh(lh(b"d0"), lh(b"d1"))
    # n=3 splits at largest power of two < 3 → [d0,d1] | [d2]
    assert merkle.merkle_root([b"d0", b"d1", b"d2"]) == nh(nh(lh(b"d0"), lh(b"d1")), lh(b"d2"))
    # n=4 → [a,b] | [c,d]
    assert merkle.merkle_root([b"a", b"b", b"c", b"d"]) == nh(nh(lh(b"a"), lh(b"b")), nh(lh(b"c"), lh(b"d")))


def test_every_leaf_has_a_verifying_inclusion_proof() -> None:
    leaves = [f"leaf-{i}".encode() for i in range(11)]  # odd, non-power-of-two
    root = merkle.merkle_root(leaves)
    for i, leaf in enumerate(leaves):
        proof = merkle.inclusion_proof(leaves, i)
        assert merkle.verify_inclusion(leaf=leaf, leaf_index=i, tree_size=len(leaves), proof=proof, root=root)


def test_verify_inclusion_rejects_out_of_range_and_wrong_leaf() -> None:
    leaves = [b"a", b"b", b"c"]
    root = merkle.merkle_root(leaves)
    proof = merkle.inclusion_proof(leaves, 0)
    # out-of-range index
    assert not merkle.verify_inclusion(leaf=b"a", leaf_index=3, tree_size=3, proof=proof, root=root)
    # right slot, wrong leaf bytes
    assert not merkle.verify_inclusion(leaf=b"forged", leaf_index=0, tree_size=3, proof=proof, root=root)


# ── HAPPY: the signed checkpoint endpoint ──────────────────────────────


def test_checkpoint_commits_to_log_and_signature_verifies(client: TestClient) -> None:
    receipts = _ingest(client, 5)
    cp = client.get("/api/checkpoint").json()
    payload = cp["payload"]

    assert payload["version"] == "aae-checkpoint/0.1"
    assert payload["tree_size"] == 5
    assert set(payload["receipt_ids"]) == {r["receipt_id"] for r in receipts}

    # Signature verifies under the chapter's advertised DID over the JCS payload.
    pub = signing.parse_did_key(cp["signer_did"])
    sig = base64.b64decode(cp["signature"])
    assert signing.verify(pub, sig, canonical_bytes(payload, include_signature=True))


def test_inclusion_proof_verifies_against_the_signed_root(client: TestClient) -> None:
    receipts = _ingest(client, 7)
    cp = client.get("/api/checkpoint").json()
    root = _unhex(cp["payload"]["merkle_root"])

    for r in receipts:
        proof = client.get(f"/api/checkpoint/proof/{r['receipt_id']}").json()
        leaf = canonical_bytes(r, include_signature=True)
        audit = [_unhex(h) for h in proof["audit_path"]]
        assert merkle.verify_inclusion(
            leaf=leaf,
            leaf_index=proof["leaf_index"],
            tree_size=proof["tree_size"],
            proof=audit,
            root=root,
        )


def test_checkpoint_is_deterministic_across_calls(client: TestClient) -> None:
    _ingest(client, 4)
    a = client.get("/api/checkpoint").json()["payload"]
    b = client.get("/api/checkpoint").json()["payload"]
    assert a["merkle_root"] == b["merkle_root"]
    assert a["receipt_ids"] == b["receipt_ids"]  # same total order


# ── ADVERSARIAL / BOUNDARY ─────────────────────────────────────────────


def test_tampered_receipt_fails_its_own_inclusion_proof(client: TestClient) -> None:
    receipts = _ingest(client, 6)
    target = receipts[2]
    proof = client.get(f"/api/checkpoint/proof/{target['receipt_id']}").json()
    root = _unhex(client.get("/api/checkpoint").json()["payload"]["merkle_root"])
    audit = [_unhex(h) for h in proof["audit_path"]]

    # The honest leaf verifies...
    honest = canonical_bytes(target, include_signature=True)
    assert merkle.verify_inclusion(
        leaf=honest,
        leaf_index=proof["leaf_index"],
        tree_size=proof["tree_size"],
        proof=audit,
        root=root,
    )
    # ...but altering any committed field breaks membership against the same root.
    forged = dict(target)
    forged["principal_did"] = "did:key:zForgedPrincipal"
    forged_leaf = canonical_bytes(forged, include_signature=True)
    assert not merkle.verify_inclusion(
        leaf=forged_leaf,
        leaf_index=proof["leaf_index"],
        tree_size=proof["tree_size"],
        proof=audit,
        root=root,
    )


def test_tampered_checkpoint_payload_fails_signature(client: TestClient) -> None:
    _ingest(client, 3)
    cp = client.get("/api/checkpoint").json()
    pub = signing.parse_did_key(cp["signer_did"])
    sig = base64.b64decode(cp["signature"])

    forged = dict(cp["payload"])
    forged["tree_size"] = 999  # claim a different log size
    assert not signing.verify(pub, sig, canonical_bytes(forged, include_signature=True))


def test_proof_for_unknown_receipt_is_404(client: TestClient) -> None:
    _ingest(client, 2)
    assert client.get("/api/checkpoint/proof/nope-not-a-real-id").status_code == 404


def test_empty_log_checkpoint_is_the_empty_root(client: TestClient) -> None:
    cp = client.get("/api/checkpoint").json()
    assert cp["payload"]["tree_size"] == 0
    assert cp["payload"]["receipt_ids"] == []
    assert cp["payload"]["merkle_root"] == "sha256:" + hashlib.sha256(b"").hexdigest()
    # nothing to prove inclusion of
    assert client.get("/api/checkpoint/proof/anything").status_code == 404
