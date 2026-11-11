"""ARP Issuer Log — ingest, verify, persist, and the live receipts surface.

The server trusts the receipt *envelope*, not the transport: a receipt is
self-authenticating via its Ed25519 signature, so verification (owned by
`sm_arp`) is the only gate. These tests issue real receipts with `sm_arp` and
drive them through the HTTP surface.

Prosecution-grade: every accept path has a hostile twin (tamper, broken chain,
cross-issuer chain confusion, replay), boundary proofs (missing/empty/unknown),
and forgery rejection.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sm_arp import Identity, build_action, chain_link, issue_receipt

from sm_server.app import create_app
from sm_server.store.sqlite import SqliteStore


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(store=SqliteStore(":memory:"), chapter_id="test-server"))


def _receipt(issuer: Identity | None = None, *, summary: str = "shared a record", **kw) -> dict:
    issuer = issuer or Identity.generate()
    return issue_receipt(
        issuer,
        principal_did=issuer.did,
        action=build_action(category="data_shared", human_summary=summary),
        **kw,
    )


# ── HAPPY ──────────────────────────────────────────────────────────


def test_ingest_persists_and_is_retrievable(client: TestClient) -> None:
    r = _receipt()
    resp = client.post("/api/receipts", json=r)
    assert resp.status_code == 200
    body = resp.json()
    assert body["accepted"] is True
    assert body["receipt_id"] == r["receipt_id"]
    assert body["chain_link"] == chain_link(r)

    recent = client.get("/api/receipts/recent").json()
    assert recent["total"] == 1
    assert recent["receipts"][0]["receipt_id"] == r["receipt_id"]

    one = client.get(f"/api/receipts/{r['receipt_id']}")
    assert one.status_code == 200
    assert one.json()["signature"] == r["signature"]


def test_recent_filters_by_principal(client: TestClient) -> None:
    a, b = Identity.generate(), Identity.generate()
    client.post("/api/receipts", json=_receipt(a))
    client.post("/api/receipts", json=_receipt(b))
    only_a = client.get("/api/receipts/recent", params={"principal": a.did}).json()
    assert {r["principal_did"] for r in only_a["receipts"]} == {a.did}
    assert only_a["total"] == 2  # total is the whole log; the list is filtered


def test_hash_chain_links_accepted(client: TestClient) -> None:
    issuer = Identity.generate()
    genesis = _receipt(issuer, summary="genesis")
    assert client.post("/api/receipts", json=genesis).json()["accepted"] is True
    linked = _receipt(issuer, summary="second", previous_receipt_hash=chain_link(genesis))
    assert client.post("/api/receipts", json=linked).json()["accepted"] is True
    assert client.get("/api/receipts/recent").json()["total"] == 2


# ── ADVERSARIAL / FAILURE ──────────────────────────────────────────


def test_tampered_receipt_rejected_and_not_persisted(client: TestClient) -> None:
    r = _receipt()
    r["action"]["human_summary"] = "rewritten after signing"
    resp = client.post("/api/receipts", json=r)
    assert resp.status_code == 200
    assert resp.json()["error"].startswith("signature")
    assert client.get("/api/receipts/recent").json()["total"] == 0


def test_broken_hash_chain_rejected(client: TestClient) -> None:
    issuer = Identity.generate()
    # Declares a predecessor link the server has never seen → genesis-with-prev.
    orphan = _receipt(issuer, previous_receipt_hash="sha256:" + "0" * 64)
    resp = client.post("/api/receipts", json=orphan)
    assert resp.json()["error"].startswith("hash_chain")
    assert client.get("/api/receipts/recent").json()["total"] == 0


def test_chain_lookup_is_scoped_per_issuer(client: TestClient) -> None:
    """A receipt from issuer B that declares issuer A's chain link must NOT
    resolve A's receipt as its predecessor — the chain is per-issuer (§6.4)."""
    a, b = Identity.generate(), Identity.generate()
    a_receipt = _receipt(a)
    client.post("/api/receipts", json=a_receipt)
    impostor = _receipt(b, previous_receipt_hash=chain_link(a_receipt))
    resp = client.post("/api/receipts", json=impostor)
    assert resp.json()["error"].startswith("hash_chain")


def test_reingest_is_idempotent(client: TestClient) -> None:
    r = _receipt()
    client.post("/api/receipts", json=r)
    client.post("/api/receipts", json=r)
    assert client.get("/api/receipts/recent").json()["total"] == 1


# ── EDGE / BOUNDARY ────────────────────────────────────────────────


def test_non_json_body_rejected(client: TestClient) -> None:
    resp = client.post("/api/receipts", content=b"not json", headers={"content-type": "application/json"})
    assert resp.status_code == 400


def test_non_object_json_rejected(client: TestClient) -> None:
    resp = client.post("/api/receipts", json=["not", "an", "object"])
    assert resp.status_code == 400


def test_unknown_receipt_is_404(client: TestClient) -> None:
    assert client.get("/api/receipts/does-not-exist").status_code == 404


# ── SURFACE ────────────────────────────────────────────────────────


def test_receipts_surface_empty(client: TestClient) -> None:
    env = client.get("/api/surfaces/receipts").json()
    assert env["version"] == "0.10"
    texts = [c.get("text") for c in env["updateComponents"]["components"]]
    assert "No receipts yet." in texts


def test_receipts_surface_lists_accepted(client: TestClient) -> None:
    client.post("/api/receipts", json=_receipt(summary="surfaced action"))
    env = client.get("/api/surfaces/receipts").json()
    blob = " ".join(str(c.get("text", "")) for c in env["updateComponents"]["components"])
    assert "surfaced action" in blob and "data_shared" in blob


# ── APPEND-ONLY (audit 2026-11 #3) ─────────────────────────────────


def test_rewrite_of_an_existing_receipt_id_is_409(client: TestClient) -> None:
    """The log used to be INSERT OR REPLACE: a valid re-signed receipt with the
    same id silently replaced history. Now it is refused and nothing changes."""
    me = Identity.generate()
    original = _receipt(me, summary="v1")
    assert client.post("/api/receipts", json=original).json()["accepted"] is True
    rewritten = _receipt(
        me, summary="REWRITTEN", receipt_id=original["receipt_id"], issued_at=original["issued_at"]
    )
    resp = client.post("/api/receipts", json=rewritten)
    assert resp.status_code == 409
    assert resp.json()["error"] == "receipt_rewrite"
    stored = client.get(f"/api/receipts/{original['receipt_id']}").json()
    assert stored["action"]["human_summary"] == "v1"
    assert client.get("/api/receipts/recent").json()["total"] == 1


def test_second_child_of_the_same_link_is_409_chain_fork(client: TestClient) -> None:
    issuer = Identity.generate()
    genesis = _receipt(issuer, summary="genesis")
    client.post("/api/receipts", json=genesis)
    child1 = _receipt(issuer, summary="child 1", previous_receipt_hash=chain_link(genesis))
    assert client.post("/api/receipts", json=child1).json()["accepted"] is True
    child2 = _receipt(issuer, summary="child 2", previous_receipt_hash=chain_link(genesis))
    resp = client.post("/api/receipts", json=child2)
    assert resp.status_code == 409 and resp.json()["error"] == "chain_fork"
    assert client.get("/api/receipts/recent").json()["total"] == 2
    # The honest child is still the one on the log, and re-posting it is still idempotent.
    assert client.post("/api/receipts", json=child1).json()["chain_link"] == chain_link(child1)
