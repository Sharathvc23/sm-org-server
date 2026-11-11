"""The protocol surface, exercised in-process via TestClient.

The umbrella conformance suite proves wire compliance against a live server;
these tests pin the same behaviour fast and offline, including the adversarial
paths the audit of 2026-11 closed: registration hijack, self-minted trust,
chapter-wide rotation nonces, and the v0.3 signing contract.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from collections.abc import Callable

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from sm_server import signing
from sm_server.app import create_app
from sm_server.store.base import Member
from sm_server.store.sqlite import SqliteStore

CHAPTER = "test-server"


@pytest.fixture
def store() -> SqliteStore:
    return SqliteStore(":memory:")


@pytest.fixture
def client(store: SqliteStore) -> TestClient:
    app = create_app(store=store, chapter_id=CHAPTER, origins={"sovereign"})
    return TestClient(app)


def _keypair() -> tuple[Ed25519PrivateKey, bytes, str]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, pub, signing.derive_did_key(pub)


def _register(client: TestClient, agent_id: str, pub: bytes, origin: str = "sovereign") -> None:
    r = client.post(
        "/api/members",
        json={
            "agent_id": agent_id,
            "name": agent_id,
            "origin": origin,
            "public_key": base64.b64encode(pub).decode(),
        },
    )
    assert r.status_code == 200 and r.json()["registered"] is True, r.text


def _v02_headers(
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


def _v03_headers(
    priv: Ed25519PrivateKey,
    agent_id: str,
    did: str,
    method: str,
    path: str,
    body: str,
    ts: str | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    ts = ts or str(int(time.time()))
    nonce = nonce or base64.b64encode(secrets.token_bytes(32)).decode()
    canonical = f"{method.upper()}:{path}:{body}:{agent_id}:{ts}:{nonce}"
    sig = base64.b64encode(priv.sign(canonical.encode())).decode()
    return {
        "X-Agent-ID": agent_id,
        "X-Agent-DID-Key": did,
        "X-Agent-Sig-Scheme": "ed25519+nonce",
        "X-Agent-Timestamp": ts,
        "X-Agent-Nonce": nonce,
        "X-Agent-Signature": sig,
    }


Signer = Callable[..., dict[str, str]]


# --- health / version / well-known / surfaces --------------------------------


def test_health_and_version(client: TestClient) -> None:
    assert client.get("/health").json()["status"] == "ok"
    v = client.get("/api/version").json()
    assert v["chapter_id"] == CHAPTER and v["protocol_versions"] == ["0.2", "0.3"]
    assert v["preferred_version"] in v["protocol_versions"]


def test_version_advertises_the_a2ui_version_surfaces_emit(client: TestClient) -> None:
    v = client.get("/api/version").json()
    emitted = client.get("/api/surfaces/docs").json()["version"]
    assert emitted in v["a2ui_versions"]
    assert v["preferred_a2ui_version"] == emitted == "0.10"
    assert "0.9" in v["a2ui_versions"]  # previous major a renderer may still negotiate


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
    _, pub, _ = _keypair()
    key = base64.b64encode(pub).decode()
    assert (
        client.post("/api/members", json={"name": "x", "origin": "sovereign", "public_key": key}).status_code
        == 400
    )
    assert (
        client.post(
            "/api/members", json={"agent_id": "x", "origin": "sovereign", "public_key": key}
        ).status_code
        == 400
    )


def test_register_rejects_unknown_origin(client: TestClient) -> None:
    r = client.post("/api/members", json={"agent_id": "a", "name": "a", "origin": "intruder"})
    assert r.status_code == 200 and "error" in r.json()


@pytest.mark.parametrize(
    "public_key",
    [
        pytest.param(None, id="absent"),
        pytest.param("", id="empty"),
        pytest.param("not base64!!", id="not-base64"),
        pytest.param(base64.b64encode(b"short").decode(), id="wrong-length"),
        pytest.param(
            base64.urlsafe_b64encode(bytes(range(32))).decode().replace("=", ""), id="url-safe-drift"
        ),
        pytest.param(12345, id="not-a-string"),
    ],
)
def test_register_requires_a_real_ed25519_public_key(client: TestClient, public_key: object) -> None:
    body: dict[str, object] = {"agent_id": "keyless", "name": "keyless", "origin": "sovereign"}
    if public_key is not None:
        body["public_key"] = public_key
    r = client.post("/api/members", json=body)
    assert r.status_code == 400, r.text
    assert "public_key" in r.json()["error"]
    assert client.get("/api/agents/keyless/trust").status_code == 404  # nothing was written


def test_register_derives_did_key_server_side(client: TestClient, store: SqliteStore) -> None:
    _, pub, did = _keypair()
    client.post(
        "/api/members",
        json={
            "agent_id": "d",
            "name": "d",
            "origin": "sovereign",
            "public_key": base64.b64encode(pub).decode(),
            "did_key": "did:key:zFORGED",
        },
    )
    m = store.get_member("d")
    assert m is not None and m.did_key == did


def test_register_rejects_non_json_and_non_object_bodies(client: TestClient) -> None:
    r = client.post(
        "/api/members", content=b"\xff\xfe not json", headers={"content-type": "application/json"}
    )
    assert r.status_code == 400
    assert client.post("/api/members", json=["a", "list"]).status_code == 400
    assert client.post("/api/members", json="just a string").status_code == 400


def test_register_same_key_is_idempotent(client: TestClient) -> None:
    _, pub, _ = _keypair()
    _register(client, "idem", pub)
    _register(client, "idem", pub)  # asserts registered: True
    assert client.get("/api/member/idem/profile").status_code == 200


def test_register_existing_id_with_different_key_is_a_hijack_attempt(
    client: TestClient, store: SqliteStore
) -> None:
    """Audit 2026-11 #1: re-registering an agent_id used to overwrite the key of record."""
    _, real_pub, real_did = _keypair()
    _register(client, "alice", real_pub)
    _, attacker_pub, _ = _keypair()
    r = client.post(
        "/api/members",
        json={
            "agent_id": "alice",
            "name": "alice",
            "origin": "sovereign",
            "public_key": base64.b64encode(attacker_pub).decode(),
        },
    )
    assert r.status_code == 401
    assert r.json() == {"error": "key_mismatch", "detail": "key_mismatch"}
    m = store.get_member("alice")
    assert m is not None and m.public_key == base64.b64encode(real_pub).decode() and m.did_key == real_did


def test_register_origin_mismatch_does_not_touch_the_record() -> None:
    c = TestClient(
        create_app(store=SqliteStore(":memory:"), chapter_id=CHAPTER, origins={"sovereign", "managed"})
    )
    _, pub, _ = _keypair()
    _register(c, "o", pub, origin="managed")
    _, pub2, _ = _keypair()
    r = c.post(
        "/api/members",
        json={
            "agent_id": "o",
            "name": "o",
            "origin": "sovereign",
            "public_key": base64.b64encode(pub2).decode(),
        },
    )
    assert r.status_code == 200 and r.json()["error"] == "origin mismatch"
    assert c.get("/api/member/o/profile").json()["origin"] == "managed"


# --- rotation ----------------------------------------------------------------


def _rotate_attestation(
    priv: Ed25519PrivateKey, agent_id: str, new_pub: bytes, nonce: str, new_did_key: str | None = None
) -> dict[str, str]:
    new_b64 = base64.b64encode(new_pub).decode()
    ts = str(int(time.time()))
    canonical = f"ROTATE:{CHAPTER}:{agent_id}:{new_b64}:{ts}:{nonce}"
    return {
        "agent_id": agent_id,
        "chapter_id": CHAPTER,
        "new_public_key_b64": new_b64,
        "new_did_key": new_did_key or signing.derive_did_key(new_pub),
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


def test_rotation_nonce_scope_is_per_agent(client: TestClient) -> None:
    """Audit 2026-11 #5: the nonce scope was chapter-wide, so any member could
    pre-burn a nonce another member was about to use."""
    priv_a, pub_a, _ = _keypair()
    priv_b, pub_b, _ = _keypair()
    _register(client, "a", pub_a)
    _register(client, "b", pub_b)
    _, new_a, _ = _keypair()
    _, new_b, _ = _keypair()
    assert client.post("/api/members/rotate", json=_rotate_attestation(priv_a, "a", new_a, "shared")).json()[
        "rotated"
    ]
    # Same nonce, different agent: fresh in its own scope.
    assert client.post("/api/members/rotate", json=_rotate_attestation(priv_b, "b", new_b, "shared")).json()[
        "rotated"
    ]


def test_rotation_ignores_client_supplied_did_key(client: TestClient, store: SqliteStore) -> None:
    priv, pub, _ = _keypair()
    _register(client, "r", pub)
    _, new_pub, new_did = _keypair()
    att = _rotate_attestation(priv, "r", new_pub, "n", new_did_key="did:key:zFORGED")
    r = client.post("/api/members/rotate", json=att).json()
    assert r["rotated"] is True and r["new_did_key"] == new_did
    m = store.get_member("r")
    assert m is not None and m.did_key == new_did


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


def test_rotation_failed_signature_does_not_consume_the_nonce(client: TestClient) -> None:
    priv, pub, _ = _keypair()
    _register(client, "rot3", pub)
    _, new_pub, _ = _keypair()
    att = _rotate_attestation(priv, "rot3", new_pub, "n-once")
    forged = {**att, "signature": base64.b64encode(b"\x00" * 64).decode()}
    assert "invalid signature" in client.post("/api/members/rotate", json=forged).json()["error"]
    assert client.post("/api/members/rotate", json=att).json()["rotated"] is True


def test_rotation_ordered_errors(client: TestClient) -> None:
    priv, pub, _ = _keypair()
    _register(client, "ord", pub)
    base = _rotate_attestation(priv, "ord", pub, "n")  # same key as old
    assert (
        client.post("/api/members/rotate", json={**base, "chapter_id": "elsewhere"})
        .json()["error"]
        .startswith("chapter_id mismatch")
    )
    assert (
        "timestamp out of window"
        in client.post("/api/members/rotate", json={**base, "timestamp": "0"}).json()["error"]
    )
    assert (
        "timestamp out of window"
        in client.post("/api/members/rotate", json={**base, "timestamp": "x"}).json()["error"]
    )
    assert (
        client.post("/api/members/rotate", json=base).json()["error"] == "new public key must differ from old"
    )
    assert (
        "wrong length"
        in client.post("/api/members/rotate", json={**base, "new_public_key_b64": "AAAA"}).json()["error"]
    )
    assert client.post("/api/members/rotate", json=[1, 2]).status_code == 400


def test_rotation_unknown_agent_rejected(client: TestClient) -> None:
    assert "error" in client.post("/api/members/rotate", json={"agent_id": "ghost"}).json()


# --- signed requests: v0.2 and v0.3 -------------------------------------------


def _feedback(client: TestClient, headers: dict[str, str], body: str) -> object:
    return client.post("/api/feedback", content=body, headers=headers)


def test_feedback_tofu_bootstraps_an_unknown_sovereign_signer(client: TestClient) -> None:
    priv, _pub, did = _keypair()
    body = json.dumps({"kind": "hello"})
    r = client.post("/api/feedback", content=body, headers=_v02_headers(priv, "tofu", did, body))
    assert r.status_code == 200 and r.json()["recorded"] is True
    profile = client.get("/api/member/tofu/profile").json()
    assert profile["origin"] == "sovereign" and profile["did_key"] == did


def test_feedback_tofu_is_disabled_when_sovereign_is_not_admitted() -> None:
    """Audit 2026-11 #2: TOFU used to mint a `sovereign` member on a deployment
    that admitted no such origin. Now an unknown signer is `no_stored_key`."""
    c = TestClient(create_app(store=SqliteStore(":memory:"), chapter_id=CHAPTER, origins={"managed"}))
    priv, _pub, did = _keypair()
    body = "{}"
    r = c.post("/api/feedback", content=body, headers=_v02_headers(priv, "stranger", did, body))
    assert r.status_code == 401 and r.json() == {"error": "no_stored_key", "detail": "no_stored_key"}
    assert c.get("/api/member/stranger/profile").status_code == 404


def test_feedback_key_mismatch_for_registered_agent(client: TestClient) -> None:
    _, real_pub, _ = _keypair()
    _register(client, "victim", real_pub)
    impostor, _, imp_did = _keypair()
    body = json.dumps({"kind": "x"})
    r = client.post("/api/feedback", content=body, headers=_v02_headers(impostor, "victim", imp_did, body))
    assert r.status_code == 401 and r.json()["detail"] == "key_mismatch"


def test_feedback_v02_replay_within_window_is_accepted(client: TestClient) -> None:
    """spec/0.2: replay protection is the timestamp window only. The umbrella
    suite (R2) asserts a byte-identical v0.2 request is accepted twice."""
    priv, pub, did = _keypair()
    _register(client, "r2", pub)
    body = "{}"
    h = _v02_headers(priv, "r2", did, body)
    assert client.post("/api/feedback", content=body, headers=h).status_code == 200
    assert client.post("/api/feedback", content=body, headers=h).status_code == 200


def test_feedback_v03_happy_path(client: TestClient) -> None:
    priv, pub, did = _keypair()
    _register(client, "v3", pub)
    body = json.dumps({"agent_id": "v3"})
    h = _v03_headers(priv, "v3", did, "POST", "/api/feedback", body)
    r = client.post("/api/feedback", content=body, headers=h)
    assert r.status_code == 200 and r.json()["recorded"] is True


def test_feedback_v03_nonce_replay_rejected(client: TestClient) -> None:
    priv, pub, did = _keypair()
    _register(client, "v3r", pub)
    body = "{}"
    h = _v03_headers(priv, "v3r", did, "POST", "/api/feedback", body)
    assert client.post("/api/feedback", content=body, headers=h).status_code == 200
    r = client.post("/api/feedback", content=body, headers=h)
    assert r.status_code == 401 and r.json() == {"error": "nonce_replay", "detail": "nonce_replay"}


def test_feedback_v03_nonce_scope_is_per_agent(client: TestClient) -> None:
    priv_a, pub_a, did_a = _keypair()
    priv_b, pub_b, did_b = _keypair()
    _register(client, "na", pub_a)
    _register(client, "nb", pub_b)
    nonce = base64.b64encode(secrets.token_bytes(32)).decode()
    ha = _v03_headers(priv_a, "na", did_a, "POST", "/api/feedback", "{}", nonce=nonce)
    hb = _v03_headers(priv_b, "nb", did_b, "POST", "/api/feedback", "{}", nonce=nonce)
    assert client.post("/api/feedback", content="{}", headers=ha).status_code == 200
    assert client.post("/api/feedback", content="{}", headers=hb).status_code == 200


def test_feedback_v03_binds_method_and_path(client: TestClient) -> None:
    """A v0.3 signature over one route must not verify on another."""
    priv, pub, did = _keypair()
    _register(client, "bind", pub)
    h = _v03_headers(priv, "bind", did, "GET", "/api/members", "")
    assert client.get("/api/members", headers=h).status_code == 200
    # Same headers (fresh nonce would be needed anyway) replayed onto feedback:
    h2 = _v03_headers(priv, "bind", did, "GET", "/api/members", "")
    r = client.post("/api/feedback", content="", headers=h2)
    assert r.status_code == 401 and r.json()["error"] == "invalid_signature"


def test_feedback_v03_binds_the_query_string(client: TestClient) -> None:
    priv, pub, did = _keypair()
    _register(client, "q", pub)
    h = _v03_headers(priv, "q", did, "GET", "/api/members?limit=5", "")
    assert client.get("/api/members?limit=5", headers=h).status_code == 200
    h = _v03_headers(priv, "q", did, "GET", "/api/members?limit=5", "")
    assert client.get("/api/members?limit=6", headers=h).json()["error"] == "invalid_signature"


def test_feedback_failed_v03_signature_does_not_burn_the_nonce(client: TestClient) -> None:
    priv, pub, did = _keypair()
    _register(client, "burn", pub)
    nonce = base64.b64encode(secrets.token_bytes(32)).decode()
    good = _v03_headers(priv, "burn", did, "POST", "/api/feedback", "{}", nonce=nonce)
    bad = {**good, "X-Agent-Signature": base64.b64encode(b"\x00" * 64).decode()}
    assert client.post("/api/feedback", content="{}", headers=bad).json()["error"] == "invalid_signature"
    assert client.post("/api/feedback", content="{}", headers=good).status_code == 200


def test_v02_signature_under_v03_scheme_header_is_rejected(client: TestClient) -> None:
    """Audit 2026-11 #4: the scheme header was ignored entirely."""
    priv, pub, did = _keypair()
    _register(client, "mixed", pub)
    body = "{}"
    h = {**_v02_headers(priv, "mixed", did, body), "X-Agent-Sig-Scheme": "ed25519+nonce"}
    assert client.post("/api/feedback", content=body, headers=h).json()["error"] == "missing_nonce"
    h["X-Agent-Nonce"] = base64.b64encode(secrets.token_bytes(32)).decode()
    assert client.post("/api/feedback", content=body, headers=h).json()["error"] == "invalid_signature"


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        pytest.param(lambda h: h.pop("X-Agent-ID"), "missing_agent_id", id="missing_agent_id"),
        pytest.param(lambda h: h.pop("X-Agent-Signature"), "missing_signature", id="missing_signature"),
        pytest.param(lambda h: h.pop("X-Agent-Timestamp"), "missing_timestamp", id="missing_timestamp"),
        pytest.param(lambda h: h.pop("X-Agent-Nonce"), "missing_nonce", id="missing_nonce"),
        pytest.param(lambda h: h.__setitem__("X-Agent-Nonce", "AAAA"), "missing_nonce", id="short_nonce"),
        pytest.param(lambda h: h.pop("X-Agent-Sig-Scheme"), "unknown_sig_scheme", id="absent_scheme"),
        pytest.param(
            lambda h: h.__setitem__("X-Agent-Sig-Scheme", "rsa-pss"),
            "unknown_sig_scheme",
            id="unknown_sig_scheme",
        ),
        pytest.param(
            lambda h: h.__setitem__("X-Agent-Timestamp", "soon"), "invalid_timestamp", id="invalid_timestamp"
        ),
        pytest.param(
            lambda h: h.__setitem__("X-Agent-Timestamp", "0"), "expired_timestamp", id="expired_timestamp"
        ),
        pytest.param(lambda h: h.pop("X-Agent-DID-Key"), "invalid_did_key", id="missing_did_key"),
        pytest.param(
            lambda h: h.__setitem__("X-Agent-DID-Key", "did:web:x"), "invalid_did_key", id="invalid_did_key"
        ),
        pytest.param(
            lambda h: h.__setitem__("X-Agent-Signature", "%%%"), "invalid_signature", id="unparsable_sig"
        ),
    ],
)
def test_closed_set_rejection_reasons(
    client: TestClient, mutate: Callable[[dict[str, str]], object], reason: str
) -> None:
    priv, pub, did = _keypair()
    _register(client, "reasons", pub)
    body = "{}"
    h = _v03_headers(priv, "reasons", did, "POST", "/api/feedback", body)
    mutate(h)
    r = client.post("/api/feedback", content=body, headers=h)
    assert r.status_code == 401, r.text
    assert r.json() == {"error": reason, "detail": reason}


def test_garbage_stored_key_is_no_stored_key_not_500(client: TestClient, store: SqliteStore) -> None:
    """Audit 2026-11 #6: an undecodable key on file used to raise inside the handler."""
    priv, _pub, did = _keypair()
    store.add_member(Member("garbage", "garbage", "sovereign", "not*base64", "did:key:zX"))
    body = "{}"
    r = client.post("/api/feedback", content=body, headers=_v02_headers(priv, "garbage", did, body))
    assert r.status_code == 401 and r.json()["error"] == "no_stored_key"


def test_feedback_legacy_header_names_are_not_honoured(client: TestClient) -> None:
    priv, pub, did = _keypair()
    _register(client, "legacy", pub)
    body = "{}"
    h = _v02_headers(priv, "legacy", did, body)
    legacy = {
        "X-Agent-Did": h["X-Agent-DID-Key"],
        "X-Timestamp": h["X-Agent-Timestamp"],
        "X-Signature": h["X-Agent-Signature"],
    }
    assert client.post("/api/feedback", content=body, headers=legacy).status_code == 401


def test_feedback_missing_headers_rejected(client: TestClient) -> None:
    assert client.post("/api/feedback", content="{}").status_code == 401


def test_feedback_stale_timestamp_rejected(client: TestClient) -> None:
    priv, _, did = _keypair()
    body = json.dumps({"kind": "x"})
    h = _v02_headers(priv, "late", did, body, ts=str(int(time.time()) - 9999))
    assert client.post("/api/feedback", content=body, headers=h).status_code == 401


# --- feedback → trust ---------------------------------------------------------


def test_self_feedback_mints_no_trust(client: TestClient) -> None:
    """Audit 2026-11 #2: every call used to credit the CALLER +1.0 regardless of body."""
    priv, pub, did = _keypair()
    _register(client, "selfish", pub)
    for body in (
        "{}",
        json.dumps({"agent_id": "selfish"}),
        json.dumps({"agent_id": "nobody-here"}),
        "[1]",
        "",
    ):
        r = client.post("/api/feedback", content=body, headers=_v02_headers(priv, "selfish", did, body))
        assert r.status_code == 200 and r.json()["recorded"] is True and r.json()["credited"] is False
    d = client.get("/api/agents/selfish/trust").json()
    assert d["score"] == 0.0 and d["history"] == []


def test_feedback_credits_a_registered_subject_once_per_day(client: TestClient) -> None:
    priv, pub, did = _keypair()
    _register(client, "voucher", pub)
    _, spub, _ = _keypair()
    _register(client, "subject", spub)
    body = json.dumps({"agent_id": "subject"})
    first = client.post(
        "/api/feedback", content=body, headers=_v02_headers(priv, "voucher", did, body)
    ).json()
    assert first["credited"] is True and first["subject"] == "subject"
    second = client.post(
        "/api/feedback", content=body, headers=_v02_headers(priv, "voucher", did, body)
    ).json()
    assert second["recorded"] is True and second["credited"] is False
    d = client.get("/api/agents/subject/trust").json()
    assert d["score"] == 1.0 and d["tier"]["min_trust"] == 0
    assert d["history"] == [{"kind": "intent_response_useful", "delta": 1.0}]
    # The voucher earned nothing by vouching.
    assert client.get("/api/agents/voucher/trust").json()["score"] == 0.0


def test_two_vouchers_each_credit_the_subject(client: TestClient) -> None:
    pa, puba, dida = _keypair()
    pb, pubb, didb = _keypair()
    _, pubs, _ = _keypair()
    _register(client, "va", puba)
    _register(client, "vb", pubb)
    _register(client, "s", pubs)
    body = json.dumps({"agent_id": "s"})
    client.post("/api/feedback", content=body, headers=_v02_headers(pa, "va", dida, body))
    client.post("/api/feedback", content=body, headers=_v02_headers(pb, "vb", didb, body))
    assert client.get("/api/agents/s/trust").json()["score"] == 2.0


def test_feedback_emits_a_chapter_signed_receipt(client: TestClient) -> None:
    """The server is a first-class ARP issuer: recording feedback also signs a
    receipt endorsing the subject (issuer=server → counterparty=subject)."""
    from sm_arp import verify_receipt

    chapter_did = client.get("/.well-known/nanda-agent.json").json()["did"]
    priv, pub, did = _keypair()
    _register(client, "m1", pub)
    _, spub, sdid = _keypair()
    _register(client, "endorsed", spub)
    body = json.dumps({"agent_id": "endorsed"})
    resp = client.post("/api/feedback", content=body, headers=_v02_headers(priv, "m1", did, body))
    rid = resp.json()["receipt_id"]

    log = client.get("/api/receipts/recent").json()
    receipt = next(r for r in log["receipts"] if r["receipt_id"] == rid)
    assert receipt["issuer_did"] == chapter_did
    assert receipt["action"]["counterparty_did"] == sdid  # the member it endorses
    assert receipt["action"]["category"] == "attestation_issued"
    assert verify_receipt(receipt).ok


def test_server_receipts_are_hash_chained(client: TestClient) -> None:
    """Audit 2026-11 #3: the server's own receipts were all genesis receipts."""
    from sm_arp import chain_link, verify_receipt

    priv, pub, did = _keypair()
    _register(client, "chain", pub)
    ids = []
    for _ in range(3):
        body = "{}"
        ids.append(
            client.post("/api/feedback", content=body, headers=_v02_headers(priv, "chain", did, body)).json()[
                "receipt_id"
            ]
        )
    receipts = {r["receipt_id"]: r for r in client.get("/api/receipts/recent").json()["receipts"]}
    first, second, third = (receipts[i] for i in ids)
    assert first.get("previous_receipt_hash") is None
    assert second["previous_receipt_hash"] == chain_link(first)
    assert third["previous_receipt_hash"] == chain_link(second)
    assert verify_receipt(third, prior=second, check_chain=True).ok


def test_trust_dossier_unknown_agent_404(client: TestClient) -> None:
    assert client.get("/api/agents/nobody/trust").status_code == 404


def test_drift_is_structurally_zero(client: TestClient) -> None:
    d = client.get("/api/admin/trust/drift").json()
    assert d == {"drift_count": 0, "drifts": []}


# --- member directory (§4.12) -------------------------------------------------


@pytest.mark.parametrize("path", ["/api/members", "/api/members/", "/api/members?skill=python"])
def test_anonymous_directory_read_is_401(client: TestClient, path: str) -> None:
    r = client.get(path, follow_redirects=False)
    assert r.status_code == 401 and r.json()["error"] == "missing_agent_id"


def test_junk_auth_headers_do_not_open_the_directory(client: TestClient) -> None:
    h = {
        "X-Agent-ID": "probe",
        "X-Agent-Signature": "AAAA",
        "X-Agent-Timestamp": str(int(time.time())),
        "X-Agent-Sig-Scheme": "not-a-real-scheme",
    }
    r = client.get("/api/members", headers=h)
    assert r.status_code == 401 and r.json()["error"] == "unknown_sig_scheme"


def test_signed_member_reads_the_directory_envelope(client: TestClient) -> None:
    priv, pub, did = _keypair()
    _register(client, "reader", pub)
    r = client.get("/api/members", headers=_v02_headers(priv, "reader", did, ""))
    assert r.status_code == 200
    body = r.json()
    assert body["chapter"] == CHAPTER
    assert body["total"] == len(body["members"]) == 1
    assert body["members"][0]["agent_id"] == "reader"


def test_directory_read_may_tofu_bootstrap(client: TestClient) -> None:
    priv, _pub, did = _keypair()
    r = client.get("/api/members", headers=_v02_headers(priv, "first-contact", did, ""))
    assert r.status_code == 200
    assert [m["agent_id"] for m in r.json()["members"]] == ["first-contact"]


def test_profile_lookup_stays_public(client: TestClient) -> None:
    _, pub, did = _keypair()
    _register(client, "pub", pub)
    r = client.get("/api/member/pub/profile")
    assert r.status_code == 200
    assert r.json() == {
        "agent_id": "pub",
        "name": "pub",
        "origin": "sovereign",
        "did_key": did,
        "chapter": CHAPTER,
    }
    assert client.get("/api/member/ghost/profile").status_code == 404


def test_member_deletes_itself_with_a_signed_request(client: TestClient) -> None:
    priv, pub, did = _keypair()
    _register(client, "leaver", pub)
    h = _v03_headers(priv, "leaver", did, "DELETE", "/api/members/leaver", "")
    r = client.delete("/api/members/leaver", headers=h)
    assert r.status_code == 200 and r.json()["deleted"] is True
    assert client.get("/api/member/leaver/profile").status_code == 404
    assert client.delete("/api/members/leaver", headers=h).status_code == 404


def test_member_cannot_delete_another_member(client: TestClient) -> None:
    priv, pub, did = _keypair()
    _, pub2, _ = _keypair()
    _register(client, "me", pub)
    _register(client, "them", pub2)
    h = _v03_headers(priv, "me", did, "DELETE", "/api/members/them", "")
    assert client.delete("/api/members/them", headers=h).status_code == 403
    assert client.get("/api/member/them/profile").status_code == 200


def test_delete_does_not_tofu(client: TestClient) -> None:
    _, pub, _ = _keypair()
    _register(client, "target", pub)
    priv, _pub2, did = _keypair()
    h = _v03_headers(priv, "target", did, "DELETE", "/api/members/target", "")
    assert client.delete("/api/members/target", headers=h).json()["error"] == "key_mismatch"
    assert client.delete("/api/members/target").status_code == 401


# --- federation --------------------------------------------------------------


def test_federation_overview_and_self_members(client: TestClient) -> None:
    priv, pub, did = _keypair()
    _register(client, "fed1", pub)
    overview = client.get("/api/federation").json()
    assert overview["self"]["agent_id"] == CHAPTER
    assert overview["total"] == len(overview["chapters"])
    members = client.get(
        f"/api/federation/{CHAPTER}/members", headers=_v02_headers(priv, "fed1", did, "")
    ).json()
    assert members["chapter"] == CHAPTER
    assert members["total"] == len(members["members"]) == 1


def test_federated_member_view_is_gated_before_peer_resolution(client: TestClient) -> None:
    assert client.get(f"/api/federation/{CHAPTER}/members").status_code == 401
    assert client.get("/api/federation/ghost-peer/members").status_code == 401


def test_federation_unknown_peer_404_for_a_signed_member(client: TestClient) -> None:
    priv, pub, did = _keypair()
    _register(client, "fed2", pub)
    r = client.get("/api/federation/ghost-peer/members", headers=_v02_headers(priv, "fed2", did, ""))
    assert r.status_code == 404


# --- config-driven origins (the neutrality seam) -----------------------------


def test_origins_are_configurable() -> None:
    app = create_app(store=SqliteStore(":memory:"), chapter_id=CHAPTER, origins={"managed"})
    c = TestClient(app)
    _, pub, _ = _keypair()
    key = base64.b64encode(pub).decode()
    ok = c.post("/api/members", json={"agent_id": "m", "name": "m", "origin": "managed", "public_key": key})
    assert ok.json()["registered"] is True
    bad = c.post(
        "/api/members", json={"agent_id": "s", "name": "s", "origin": "sovereign", "public_key": key}
    )
    assert "error" in bad.json()


def test_nonrotatable_origin_cannot_rotate() -> None:
    app = create_app(
        store=SqliteStore(":memory:"),
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


# --- startup configuration ----------------------------------------------------


def test_production_without_seed_fails_at_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SERVER_SEED", raising=False)
    monkeypatch.delenv("CHAPTER_SEED", raising=False)
    monkeypatch.setenv("SERVER_ENV", "production")
    with pytest.raises(RuntimeError, match="SERVER_SEED"):
        create_app(store=SqliteStore(":memory:"), chapter_id=CHAPTER)


def test_seed_makes_the_server_identity_stable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SERVER_SEED", base64.b64encode(bytes(range(32))).decode())
    a = TestClient(create_app(store=SqliteStore(":memory:"), chapter_id=CHAPTER))
    b = TestClient(create_app(store=SqliteStore(":memory:"), chapter_id=CHAPTER))
    assert (
        a.get("/.well-known/nanda-agent.json").json()["did"]
        == b.get("/.well-known/nanda-agent.json").json()["did"]
    )


@pytest.mark.parametrize("seed", ["not base64", base64.b64encode(b"short").decode()])
def test_malformed_seed_fails_at_startup(monkeypatch: pytest.MonkeyPatch, seed: str) -> None:
    monkeypatch.setenv("SERVER_SEED", seed)
    with pytest.raises(RuntimeError, match="SERVER_SEED"):
        create_app(store=SqliteStore(":memory:"), chapter_id=CHAPTER)


def test_default_store_is_a_file_closed_on_shutdown(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = tmp_path / "default.sqlite"
    monkeypatch.setenv("SERVER_DB_PATH", str(db))
    _, pub, _ = _keypair()
    with TestClient(create_app(chapter_id=CHAPTER)) as c:
        _register(c, "durable", pub)
    assert db.exists()
    with TestClient(create_app(chapter_id=CHAPTER)) as c:
        assert c.get("/api/member/durable/profile").status_code == 200


# --- conformance badge at the canonical well-known URL ----------------------


def test_conformance_badge_served_and_advertised(tmp_path, monkeypatch) -> None:
    badge = tmp_path / "conformance.json"
    badge.write_text(json.dumps({"payload": {"runtime": "sm-org-server"}, "signature": "sig"}))
    monkeypatch.setenv("CHAPTER_BADGE_PATH", str(badge))
    c = TestClient(create_app(store=SqliteStore(":memory:"), chapter_id=CHAPTER))
    r = c.get("/.well-known/conformance.json")
    assert r.status_code == 200 and r.json()["payload"]["runtime"] == "sm-org-server"
    wk = c.get("/.well-known/nanda-agent.json").json()
    assert wk["conformance"].endswith("/.well-known/conformance.json")


def test_conformance_badge_404_and_unadvertised_when_absent(monkeypatch) -> None:
    monkeypatch.setenv("CHAPTER_BADGE_PATH", "/nonexistent/conformance.json")
    c = TestClient(create_app(store=SqliteStore(":memory:"), chapter_id=CHAPTER))
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
    c = TestClient(create_app(store=SqliteStore(":memory:"), chapter_id=CHAPTER))
    r = c.get("/.well-known/arp-conformance.json")
    assert r.status_code == 200 and r.json()["payload"]["runtime"] == "sm-org-server"
    wk = c.get("/.well-known/nanda-agent.json").json()
    assert wk["arp_conformance"].endswith("/.well-known/arp-conformance.json")


def test_arp_badge_404_and_unadvertised_when_absent(monkeypatch) -> None:
    monkeypatch.setenv("CHAPTER_ARP_BADGE_PATH", "/nonexistent/arp-conformance.json")
    c = TestClient(create_app(store=SqliteStore(":memory:"), chapter_id=CHAPTER))
    assert c.get("/.well-known/arp-conformance.json").status_code == 404
    assert "arp_conformance" not in c.get("/.well-known/nanda-agent.json").json()
