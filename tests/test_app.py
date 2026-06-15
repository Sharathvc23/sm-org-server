"""The protocol surface, exercised in-process via TestClient.

The umbrella conformance suite proves wire compliance against a live server;
these tests pin the same behaviour fast and offline, including the happy paths
the conformance suite can only reach with multi-server or seeded fixtures.
"""

from __future__ import annotations

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from sm_server import signing
from sm_server.app import create_app
from sm_server.store.sqlite import SqliteStore

CHAPTER = "test-server"


@pytest.fixture
def client() -> TestClient:
    app = create_app(store=SqliteStore(), chapter_id=CHAPTER, origins={"sovereign"})
    return TestClient(app)


def _keypair() -> tuple[Ed25519PrivateKey, bytes, str]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, pub, signing.derive_did_key(pub)


def _register(client: TestClient, agent_id: str, pub: bytes) -> None:
    r = client.post(
        "/api/members",
        json={
            "agent_id": agent_id,
            "name": agent_id,
            "origin": "sovereign",
            "public_key": base64.b64encode(pub).decode(),
        },
    )
    assert r.status_code == 200 and r.json()["registered"] is True


def _signed_feedback_headers(
    priv: Ed25519PrivateKey, agent_id: str, did: str, body: str, ts: str | None = None
) -> dict[str, str]:
    ts = ts or str(int(time.time()))
    sig = base64.b64encode(priv.sign(f"{body}:{agent_id}:{ts}".encode())).decode()
    return {
        "X-Agent-ID": agent_id,
        "X-Agent-DID-Key": did,
        "X-Agent-Sig-Scheme": "ed25519",
        "X-Agent-Timestamp": ts,
        "X-Agent-Signature": sig,
    }


# --- health / version / well-known / surfaces --------------------------------


def test_health_and_version(client: TestClient) -> None:
    assert client.get("/health").json()["status"] == "ok"
    v = client.get("/api/version").json()
    assert v["chapter_id"] == CHAPTER and "0.3" in v["protocol_versions"]


def test_well_known_has_federation_substrate(client: TestClient) -> None:
    wk = client.get("/.well-known/nanda-agent.json").json()
    assert wk["agent_id"] == CHAPTER
    assert wk["did"].startswith("did:key:z")
    assert wk["facts_url"].startswith("https://")
    assert isinstance(wk["registries"], dict)


def test_public_surface_validates_shape(client: TestClient) -> None:
    env = client.get("/api/surfaces/docs").json()
    assert env["version"] == "0.10"
    assert env["createSurface"]["surfaceId"] == "docs"
    assert env["updateComponents"]["components"], "surface must carry components"


def test_auth_gated_surface_is_forbidden_unsigned(client: TestClient) -> None:
    assert client.get("/api/surfaces/today").status_code == 403


def test_unknown_surface_is_404(client: TestClient) -> None:
    assert client.get("/api/surfaces/nope").status_code == 404


# --- register ----------------------------------------------------------------


def test_register_rejects_missing_field(client: TestClient) -> None:
    assert client.post("/api/members", json={"name": "x", "origin": "sovereign"}).status_code == 400


def test_register_rejects_unknown_origin(client: TestClient) -> None:
    r = client.post("/api/members", json={"agent_id": "a", "name": "a", "origin": "intruder"})
    assert r.status_code == 200 and "error" in r.json()


# --- rotation ----------------------------------------------------------------


def _rotate_attestation(priv: Ed25519PrivateKey, agent_id: str, new_pub: bytes, nonce: str) -> dict[str, str]:
    new_b64 = base64.b64encode(new_pub).decode()
    ts = str(int(time.time()))
    canonical = f"ROTATE:{CHAPTER}:{agent_id}:{new_b64}:{ts}:{nonce}"
    return {
        "agent_id": agent_id,
        "chapter_id": CHAPTER,
        "new_public_key_b64": new_b64,
        "new_did_key": signing.derive_did_key(new_pub),
        "timestamp": ts,
        "nonce": nonce,
        "signature": base64.b64encode(priv.sign(canonical.encode())).decode(),
    }


def test_rotation_happy_path_and_replay(client: TestClient) -> None:
    priv1, pub1, _ = _keypair()
    _register(client, "rot", pub1)
    priv2, pub2, _ = _keypair()
    priv3, pub3, _ = _keypair()
    # rotation 1: key1 → key2, signed by key1, nonce "n1"
    att1 = _rotate_attestation(priv1, "rot", pub2, "n1")
    assert client.post("/api/members/rotate", json=att1).json()["rotated"] is True
    # rotation 2: key2 → key3, signed by the now-current key2, REUSING nonce "n1"
    att2 = _rotate_attestation(priv2, "rot", pub3, "n1")
    assert client.post("/api/members/rotate", json=att2).json()["error"] == "nonce replay"


def test_rotation_forged_signature_rejected(client: TestClient) -> None:
    priv, pub, _ = _keypair()
    _register(client, "rot2", pub)
    _, new_pub, _ = _keypair()
    new_b64 = base64.b64encode(new_pub).decode()
    ts = str(int(time.time()))
    att = {
        "agent_id": "rot2",
        "chapter_id": CHAPTER,
        "new_public_key_b64": new_b64,
        "timestamp": ts,
        "nonce": "n",
        "signature": base64.b64encode(b"\x00" * 64).decode(),
    }
    assert "invalid signature" in client.post("/api/members/rotate", json=att).json()["error"]


def test_rotation_unknown_agent_rejected(client: TestClient) -> None:
    assert "error" in client.post("/api/members/rotate", json={"agent_id": "ghost"}).json()


# --- signed feedback + trust ledger ------------------------------------------


def test_feedback_tofu_then_trust_dossier_moves(client: TestClient) -> None:
    priv, pub, did = _keypair()
    body = json.dumps({"kind": "intent_response_useful"})
    h = _signed_feedback_headers(priv, "tofu", did, body)
    r = client.post("/api/feedback", content=body, headers=h)
    assert r.status_code == 200 and r.json()["recorded"] is True
    d = client.get("/api/agents/tofu/trust").json()
    assert d["score"] == 1.0 and d["tier"]["min_trust"] == 0
    assert d["history"][0]["kind"] == "intent_response_useful"


def test_feedback_key_mismatch_for_registered_agent(client: TestClient) -> None:
    _, real_pub, _ = _keypair()
    _register(client, "victim", real_pub)
    impostor, _, imp_did = _keypair()
    body = json.dumps({"kind": "x"})
    h = _signed_feedback_headers(impostor, "victim", imp_did, body)
    r = client.post("/api/feedback", content=body, headers=h)
    assert r.status_code == 401 and r.json()["detail"] == "key_mismatch"


def test_feedback_missing_headers_rejected(client: TestClient) -> None:
    assert client.post("/api/feedback", content="{}").status_code == 401


def test_feedback_emits_a_chapter_signed_receipt(client: TestClient) -> None:
    """The server is a first-class ARP issuer: recording feedback also signs a
    receipt endorsing the member (issuer=server → counterparty=member)."""
    from sm_arp import verify_receipt

    chapter_did = client.get("/.well-known/nanda-agent.json").json()["did"]
    priv, _pub, did = _keypair()
    body = json.dumps({"kind": "intent_response_useful"})
    resp = client.post("/api/feedback", content=body, headers=_signed_feedback_headers(priv, "m1", did, body))
    rid = resp.json()["receipt_id"]

    log = client.get("/api/receipts/recent").json()
    receipt = next(r for r in log["receipts"] if r["receipt_id"] == rid)
    assert receipt["issuer_did"] == chapter_did
    assert receipt["action"]["counterparty_did"] == did  # the member it endorses
    assert receipt["action"]["category"] == "attestation_issued"
    assert verify_receipt(receipt).ok


def test_feedback_stale_timestamp_rejected(client: TestClient) -> None:
    priv, _, did = _keypair()
    body = json.dumps({"kind": "x"})
    h = _signed_feedback_headers(priv, "late", did, body, ts=str(int(time.time()) - 9999))
    assert client.post("/api/feedback", content=body, headers=h).status_code == 401


def test_trust_dossier_unknown_agent_404(client: TestClient) -> None:
    assert client.get("/api/agents/nobody/trust").status_code == 404


def test_drift_is_structurally_zero(client: TestClient) -> None:
    d = client.get("/api/admin/trust/drift").json()
    assert d == {"drift_count": 0, "drifts": []}


# --- federation --------------------------------------------------------------


def test_federation_overview_and_self_members(client: TestClient) -> None:
    _, pub, _ = _keypair()
    _register(client, "fed1", pub)
    overview = client.get("/api/federation").json()
    assert overview["self"]["agent_id"] == CHAPTER
    assert overview["total"] == len(overview["chapters"])
    members = client.get(f"/api/federation/{CHAPTER}/members").json()
    assert members["chapter"] == CHAPTER
    assert members["total"] == len(members["members"]) == 1


def test_federation_unknown_peer_404(client: TestClient) -> None:
    assert client.get("/api/federation/ghost-peer/members").status_code == 404


# --- config-driven origins (the neutrality seam) -----------------------------


def test_origins_are_configurable() -> None:
    app = create_app(store=SqliteStore(), chapter_id=CHAPTER, origins={"managed"})
    c = TestClient(app)
    ok = c.post("/api/members", json={"agent_id": "m", "name": "m", "origin": "managed"})
    assert ok.json()["registered"] is True
    bad = c.post("/api/members", json={"agent_id": "s", "name": "s", "origin": "sovereign"})
    assert "error" in bad.json()


def test_nonrotatable_origin_cannot_rotate() -> None:
    app = create_app(
        store=SqliteStore(),
        chapter_id=CHAPTER,
        origins={"managed"},
        nonrotatable_origins={"managed"},
    )
    c = TestClient(app)
    priv, pub, _ = _keypair()
    c.post(
        "/api/members",
        json={
            "agent_id": "m",
            "name": "m",
            "origin": "managed",
            "public_key": base64.b64encode(pub).decode(),
        },
    )
    out = c.post("/api/members/rotate", json={"agent_id": "m", "chapter_id": CHAPTER}).json()
    assert "may not self-rotate" in out["error"]


# --- conformance badge at the canonical well-known URL ----------------------


def test_conformance_badge_served_and_advertised(tmp_path, monkeypatch) -> None:
    badge = tmp_path / "conformance.json"
    badge.write_text(json.dumps({"payload": {"runtime": "sm-org-server"}, "signature": "sig"}))
    monkeypatch.setenv("CHAPTER_BADGE_PATH", str(badge))
    c = TestClient(create_app(store=SqliteStore(), chapter_id=CHAPTER))
    r = c.get("/.well-known/conformance.json")
    assert r.status_code == 200 and r.json()["payload"]["runtime"] == "sm-org-server"
    wk = c.get("/.well-known/nanda-agent.json").json()
    assert wk["conformance"].endswith("/.well-known/conformance.json")


def test_conformance_badge_404_and_unadvertised_when_absent(monkeypatch) -> None:
    monkeypatch.setenv("CHAPTER_BADGE_PATH", "/nonexistent/conformance.json")
    c = TestClient(create_app(store=SqliteStore(), chapter_id=CHAPTER))
    assert c.get("/.well-known/conformance.json").status_code == 404
    assert "conformance" not in c.get("/.well-known/nanda-agent.json").json()


def test_arp_badge_served_and_advertised(tmp_path, monkeypatch) -> None:
    badge = tmp_path / "arp-conformance.json"
    badge.write_text(
        json.dumps(
            {
                "payload": {
                    "runtime": "sm-org-server",
                    "extensions": {"arp.conformance.profile": "receipts-0.1"},
                },
                "signature": "sig",
            }
        )
    )
    monkeypatch.setenv("CHAPTER_ARP_BADGE_PATH", str(badge))
    c = TestClient(create_app(store=SqliteStore(), chapter_id=CHAPTER))
    r = c.get("/.well-known/arp-conformance.json")
    assert r.status_code == 200 and r.json()["payload"]["runtime"] == "sm-org-server"
    wk = c.get("/.well-known/nanda-agent.json").json()
    assert wk["arp_conformance"].endswith("/.well-known/arp-conformance.json")


def test_arp_badge_404_and_unadvertised_when_absent(monkeypatch) -> None:
    monkeypatch.setenv("CHAPTER_ARP_BADGE_PATH", "/nonexistent/arp-conformance.json")
    c = TestClient(create_app(store=SqliteStore(), chapter_id=CHAPTER))
    assert c.get("/.well-known/arp-conformance.json").status_code == 404
    assert "arp_conformance" not in c.get("/.well-known/nanda-agent.json").json()
