"""The conformant protocol surface — minimal, backend-agnostic.

Implements exactly what `conformance/server/` requires of a server, against the
`ServerStore` interface. No LLM, no think-cycle, no specific database — the
agent's intelligence and governance live above this, as product or plugins.
"""

from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from sm_arp import Identity as ArpIdentity
from sm_arp import build_action, issue_receipt, verify_receipt

from sm_server import merkle, signing, trust
from sm_server.store.base import Member, ServerStore
from sm_server.store.sqlite import SqliteStore

ROTATION_WINDOW_S = 300
SIGNED_REQUEST_WINDOW_S = 300

# Origin vocabulary is policy, not protocol: the core ships neutral and a deployment
# declares which origins it admits (and which may not self-rotate keys, e.g. managed
# install-time identities) via config. No runtime-specific name is baked into source.
DEFAULT_ORIGINS = ("sovereign",)


def _env(*names: str, default: str | None = None) -> str | None:
    """First set value among ``names`` (new name first, legacy aliases after).

    Env vars were renamed ``CHAPTER_*`` → ``SERVER_*`` with the brand; the legacy
    names are still read so already-deployed operators don't break.
    """
    for name in names:
        value = os.environ.get(name)
        if value is not None:
            return value
    return default


def _origins_from_env(var: str, legacy: str, default: tuple[str, ...]) -> set[str]:
    raw = _env(var, legacy, default="") or ""
    declared = {o.strip() for o in raw.split(",") if o.strip()}
    return declared or set(default)


def _surface(page_id: str, *components: dict[str, object]) -> dict[str, object]:
    """A v0.10 A2UI surface envelope — the wire shape every renderer agrees on."""
    return {
        "createSurface": {"surfaceId": page_id},
        "updateComponents": {
            "surfaceId": page_id,
            "root": components[0]["id"] if components else "root",
            "components": list(components),
        },
        "version": "0.10",
    }


def _receipts_surface(receipts: list[dict[str, object]]) -> dict[str, object]:
    """A live A2UI view of the Issuer Log — the server's accepted receipts."""
    comps: list[dict[str, object]] = [
        {"id": "h", "component": "Heading", "text": "Issuer Log", "level": 1},
    ]
    if not receipts:
        comps.append({"id": "empty", "component": "Text", "text": "No receipts yet."})
    for idx, r in enumerate(receipts):
        action = r.get("action")
        action = action if isinstance(action, dict) else {}
        line = f"{r.get('issued_at', '')} · {action.get('category', '')} · {action.get('human_summary', '')}"
        comps.append({"id": f"r{idx}", "component": "Text", "text": line})
    return _surface("receipts", *comps)


AUTH_GATED_SURFACES = {"today"}
DYNAMIC_SURFACES = {"receipts"}

PUBLIC_SURFACES = {
    "docs": _surface(
        "docs",
        {"id": "h", "component": "Heading", "text": "Server documentation", "level": 1},
        {"id": "body", "component": "Markdown", "text": "## Joining\n\nRegister, then sign your requests."},
    ),
    "chronicle": _surface(
        "chronicle",
        {"id": "h", "component": "Heading", "text": "Server chronicle", "level": 1},
        {"id": "body", "component": "Text", "text": "A running record of server activity."},
    ),
}


def _ordered_issuer_log(store: ServerStore) -> list[dict[str, object]]:
    """The whole Issuer Log in one canonical, total order.

    Shared by the checkpoint and its proofs so leaf indices line up. Fetched
    *uncapped* (``receipt_count()`` as the limit) so the checkpoint commits to
    the entire log, never a silent prefix; ordered by ``(issued_at, receipt_id)``
    — total and stable, independent of the store's own row order.
    """
    receipts = store.list_receipts(store.receipt_count())
    return sorted(receipts, key=lambda r: (str(r.get("issued_at", "")), str(r.get("receipt_id", ""))))


def create_app(
    store: ServerStore | None = None,
    chapter_id: str | None = None,
    origins: set[str] | None = None,
    nonrotatable_origins: set[str] | None = None,
) -> FastAPI:
    store = store or SqliteStore()
    # `chapter_id` is the frozen wire field (the server's identifier on the wire); the
    # env var that sets it is the new `SERVER_ID` (legacy `CHAPTER_ID` still honored).
    chapter_id = chapter_id or _env("SERVER_ID", "CHAPTER_ID", default="sm-server") or "sm-server"
    _public_url = _env("SERVER_PUBLIC_URL", "CHAPTER_PUBLIC_URL", default="https://server.local") or ""
    base_url = _public_url.rstrip("/")
    valid_origins = (
        origins
        if origins is not None
        else _origins_from_env("SERVER_ORIGINS", "CHAPTER_ORIGINS", DEFAULT_ORIGINS)
    )
    nonrotatable = (
        nonrotatable_origins
        if nonrotatable_origins is not None
        else _origins_from_env("SERVER_NONROTATABLE_ORIGINS", "CHAPTER_NONROTATABLE_ORIGINS", ())
    )
    # The server's own ARP signing identity — it issues receipts for server
    # actions, not just stores members'. Stable across restarts when SERVER_SEED
    # (base64 of a 32-byte Ed25519 seed) is set; ephemeral otherwise.
    _seed = _env("SERVER_SEED", "CHAPTER_SEED")
    server_identity = ArpIdentity.from_seed(base64.b64decode(_seed)) if _seed else ArpIdentity.generate()
    server_did = server_identity.did

    # Signed conformance badges, served publicly (the canonical URLs across all
    # servers). Read once; absent → endpoint 404s and the well-known doc omits the
    # pointer. The wire badge attests the server protocol suite; the ARP badge
    # attests the receipt suite (a distinct corpus, hence a distinct file).
    def _load_badge(env_var: str, legacy_var: str, default: str) -> dict[str, object] | None:
        path = Path(_env(env_var, legacy_var, default=default) or default)
        try:
            return json.loads(path.read_text()) if path.exists() else None
        except (OSError, ValueError):
            return None

    conformance_badge_doc = _load_badge("SERVER_BADGE_PATH", "CHAPTER_BADGE_PATH", ".nanda/conformance.json")
    arp_badge_doc = _load_badge(
        "SERVER_ARP_BADGE_PATH", "CHAPTER_ARP_BADGE_PATH", ".nanda/arp-conformance.json"
    )
    app = FastAPI(title="sm-server")

    def emit_server_receipt(
        principal_did: str,
        *,
        category: str,
        human_summary: str,
        counterparty_did: str | None = None,
        counterparty_label: str | None = None,
    ) -> dict[str, object]:
        """Sign and persist a receipt for a server action, into the Issuer Log.

        The server is a first-class ARP issuer: actions it takes (attesting an
        interaction, endorsing a member) produce signed receipts the same way a
        member's do. The edge (issuer=server → counterparty) is what the
        reputation layer reads, so this is how a server's endorsement counts.
        """
        action = build_action(
            category=category,
            human_summary=human_summary,
            counterparty_did=counterparty_did,
            counterparty_label=counterparty_label,
        )
        receipt: dict[str, object] = issue_receipt(
            server_identity, principal_did=principal_did, action=action
        )
        store.append_receipt(receipt)
        return receipt

    @app.get("/health")
    def health() -> dict[str, object]:
        return {"status": "ok", "agent_id": chapter_id, "members": store.member_count(), "federation": 0}

    @app.get("/api/version")
    def version() -> dict[str, object]:
        return {
            "chapter_id": chapter_id,
            "protocol_versions": ["0.2", "0.3"],
            "preferred_version": "0.3",
            "a2ui_versions": ["0.9"],
            "preferred_a2ui_version": "0.9",
        }

    @app.post("/api/members")
    async def register(req: Request) -> JSONResponse:
        body = await req.json()
        agent_id, name = body.get("agent_id"), body.get("name")
        if not agent_id or not name:
            return JSONResponse({"error": "agent_id and name required"}, status_code=400)
        origin = body.get("origin")
        if origin not in valid_origins:
            return JSONResponse(
                {"error": f"invalid origin: must be one of {sorted(valid_origins)}"},
                status_code=200,
            )
        existing = store.get_member(agent_id)
        if existing is not None and existing.origin != origin:
            return JSONResponse(
                {"error": "origin mismatch", "existing_origin": existing.origin}, status_code=200
            )
        public_key = body.get("public_key", "")
        try:
            did_key = signing.derive_did_key(base64.b64decode(public_key)) if public_key else ""
        except Exception:
            did_key = ""
        store.put_member(Member(agent_id, name, origin, public_key, did_key))
        return JSONResponse(
            {"agent_id": agent_id, "registered": True, "chapter": chapter_id, "origin": origin}
        )

    @app.post("/api/members/rotate")
    async def rotate(req: Request) -> JSONResponse:
        a = await req.json()
        agent_id = a.get("agent_id")
        member = store.get_member(agent_id)
        if member is None:
            return JSONResponse({"error": "unknown agent — cannot rotate an unregistered key"})
        # §4.2 ordered checks; rejections return {"error": ...} with HTTP 200.
        if member.origin in nonrotatable:
            return JSONResponse(
                {"error": f"origin '{member.origin}' may not self-rotate keys (managed identity)"}
            )
        if a.get("chapter_id") != chapter_id:
            return JSONResponse({"error": f"chapter_id mismatch (attestation is for {a.get('chapter_id')})"})
        ts = a.get("timestamp")
        try:
            if abs(int(time.time()) - int(ts)) > ROTATION_WINDOW_S:
                return JSONResponse({"error": f"timestamp out of window (max {ROTATION_WINDOW_S}s)"})
        except (TypeError, ValueError):
            return JSONResponse({"error": f"timestamp out of window (max {ROTATION_WINDOW_S}s)"})
        new_pk_b64 = a.get("new_public_key_b64", "")
        if new_pk_b64 == member.public_key:
            return JSONResponse({"error": "new public key must differ from old"})
        try:
            new_raw = base64.b64decode(new_pk_b64)
        except Exception:
            new_raw = b""
        if len(new_raw) != 32:
            return JSONResponse({"error": f"new pubkey wrong length: {len(new_raw)} (Ed25519 needs 32)"})
        nonce = a.get("nonce", "")
        canonical = f"ROTATE:{a.get('chapter_id')}:{agent_id}:{new_pk_b64}:{ts}:{nonce}"
        try:
            ok = signing.verify(
                base64.b64decode(member.public_key),
                base64.b64decode(a.get("signature", "")),
                canonical.encode(),
            )
        except Exception:
            ok = False
        if not ok:
            return JSONResponse({"error": "invalid signature (old key did not sign this attestation)"})
        if not store.consume_nonce(chapter_id, nonce):
            return JSONResponse({"error": "nonce replay"})
        new_did = a.get("new_did_key") or signing.derive_did_key(new_raw)
        store.rotate_key(agent_id, new_pk_b64, new_did)
        return JSONResponse({"agent_id": agent_id, "rotated": True, "new_public_key_b64": new_pk_b64})

    @app.get("/api/members")
    def list_members(limit: int = 50) -> dict[str, object]:
        members = store.list_members(limit)
        return {
            "members": [
                {"agent_id": m.agent_id, "name": m.name, "origin": m.origin, "did_key": m.did_key}
                for m in members
            ],
            "total": store.member_count(),
        }

    @app.post("/api/feedback")
    async def feedback(req: Request) -> JSONResponse:
        # Signed-request verification (spec/0.2 §3.1). The body is signed verbatim,
        # so we read the raw bytes — re-serialising would change the canonical string.
        raw = await req.body()
        h = req.headers
        agent_id = h.get("x-agent-id")
        did_key_hdr = h.get("x-agent-did-key")
        ts = h.get("x-agent-timestamp")
        sig_b64 = h.get("x-agent-signature")
        if not (agent_id and did_key_hdr and ts and sig_b64):
            raise HTTPException(status_code=401, detail="missing v0.2 signed-request headers")
        try:
            if abs(int(time.time()) - int(ts)) > SIGNED_REQUEST_WINDOW_S:
                raise HTTPException(status_code=401, detail="timestamp out of window")
        except (TypeError, ValueError):
            raise HTTPException(status_code=401, detail="malformed timestamp") from None
        try:
            claimed_pub = signing.parse_did_key(did_key_hdr)
            sig = base64.b64decode(sig_b64)
        except Exception:
            raise HTTPException(status_code=401, detail="malformed did-key or signature") from None
        canonical = f"{raw.decode('utf-8', 'strict')}:{agent_id}:{ts}".encode()

        member = store.get_member(agent_id)
        if member is not None:
            # Registered: the presented key MUST be the one on file (TOFU idempotence).
            if claimed_pub != base64.b64decode(member.public_key):
                raise HTTPException(status_code=401, detail="key_mismatch")
            if not signing.verify(claimed_pub, sig, canonical):
                raise HTTPException(status_code=401, detail="invalid signature")
        else:
            # Trust on first use: record the presented key as authoritative.
            if not signing.verify(claimed_pub, sig, canonical):
                raise HTTPException(status_code=401, detail="invalid signature")
            pub_b64 = base64.b64encode(claimed_pub).decode()
            store.put_member(Member(agent_id, agent_id, "sovereign", pub_b64, did_key_hdr))

        useful = trust.EVENT_DELTAS["intent_response_useful"]
        store.record_trust_event(agent_id, "intent_response_useful", useful)
        # The server attests the interaction with a signed receipt — its
        # endorsement of the member (issuer=server → counterparty=member),
        # which is what the reputation layer reads. Emission is default, not opt-in.
        receipt = emit_server_receipt(
            server_did,
            category="attestation_issued",
            human_summary=f"Attested a useful intent response from member {agent_id}"[:280],
            counterparty_did=did_key_hdr,
            counterparty_label=agent_id,
        )
        return JSONResponse({"recorded": True, "agent_id": agent_id, "receipt_id": receipt["receipt_id"]})

    @app.get("/api/agents/{agent_id}/trust")
    def trust_dossier(agent_id: str) -> JSONResponse:
        if store.get_member(agent_id) is None:
            raise HTTPException(status_code=404, detail="unknown agent")
        score = store.trust_score(agent_id)
        row = trust.tier_for(score)
        return JSONResponse(
            {
                "agent_id": agent_id,
                "score": score,
                "tier": {
                    "name": row["tier"],
                    "min_trust": row["score_min"],
                    "can_federate": row["federate"],
                    "open_calls_max": row["open_calls_max"],
                    "ttl_days": row["ttl_days"],
                },
                "next_tier_min": trust.next_tier_min(score),
                "history": store.trust_history(agent_id),
            }
        )

    @app.get("/api/admin/trust/drift")
    def trust_drift() -> dict[str, object]:
        # Score is the authoritative SUM of deltas, so stored == recomputed by construction.
        return {"drift_count": 0, "drifts": []}

    @app.post("/api/receipts")
    async def ingest_receipt(req: Request) -> JSONResponse:
        """Verify and persist one ARP receipt to the Issuer Log.

        The receipt is self-authenticating — its Ed25519 signature over the
        canonical bytes binds it to ``issuer_did`` no matter who POSTs it — so
        the server trusts the envelope, not the transport. `sm_arp` owns the
        verification; on failure nothing is written.
        """
        try:
            receipt = await req.json()
        except Exception:
            return JSONResponse({"error": "body is not valid JSON"}, status_code=400)
        if not isinstance(receipt, dict):
            return JSONResponse({"error": "receipt must be a JSON object"}, status_code=400)

        # Resolve the per-issuer predecessor for the hash chain (§6.4), if declared.
        prev = receipt.get("previous_receipt_hash")
        prior = None
        if prev:
            issuer = receipt.get("issuer_did")
            if isinstance(issuer, str) and isinstance(prev, str):
                prior = store.get_receipt_by_chain_link(issuer, prev)

        result = verify_receipt(receipt, mode="strict", prior=prior, check_chain=bool(prev))
        if not result.ok:
            # A receipt that fails verification is a bad payload, not a missing-auth
            # request — mirror /api/members/rotate: HTTP 200 with an {"error": ...} body.
            return JSONResponse({"error": f"{result.stage}: {result.detail}"})

        link = store.append_receipt(receipt)
        return JSONResponse({"accepted": True, "receipt_id": receipt["receipt_id"], "chain_link": link})

    @app.get("/api/receipts/recent")
    def recent_receipts(limit: int = 50, principal: str | None = None) -> dict[str, object]:
        receipts = (
            store.list_receipts_for_principal(principal, limit) if principal else store.list_receipts(limit)
        )
        return {"receipts": receipts, "total": store.receipt_count()}

    @app.get("/api/receipts/{receipt_id}")
    def get_receipt(receipt_id: str) -> JSONResponse:
        receipt = store.get_receipt(receipt_id)
        if receipt is None:
            raise HTTPException(status_code=404, detail="unknown receipt")
        return JSONResponse(receipt)

    @app.get("/api/checkpoint")
    def checkpoint() -> JSONResponse:
        """A signed RFC 6962 Merkle checkpoint over the whole Issuer Log.

        The receipt hash chain proves *forward* tamper-evidence within an issuer;
        this proves *membership* across the whole log: anyone holding a receipt,
        its inclusion proof, and this signed root can verify it offline.
        """
        receipts = _ordered_issuer_log(store)
        return JSONResponse(merkle.build_checkpoint(receipts, identity=server_identity))

    @app.get("/api/checkpoint/proof/{receipt_id}")
    def checkpoint_proof(receipt_id: str) -> JSONResponse:
        """RFC 6962 inclusion proof for one receipt against the current root.

        Taken over the same ordering as ``/api/checkpoint`` so ``leaf_index``
        lines up with the signed root.
        """
        receipts = _ordered_issuer_log(store)
        index = next((i for i, r in enumerate(receipts) if r.get("receipt_id") == receipt_id), None)
        if index is None:
            raise HTTPException(status_code=404, detail="unknown receipt")
        leaves = merkle.checkpoint_leaves(receipts)
        path = merkle.inclusion_proof(leaves, index)
        root = merkle.merkle_root(leaves)
        return JSONResponse(
            {
                "receipt_id": receipt_id,
                "leaf_index": index,
                "tree_size": len(receipts),
                "merkle_root": "sha256:" + root.hex(),
                "audit_path": ["sha256:" + h.hex() for h in path],
            }
        )

    @app.get("/api/surfaces/{page_id}")
    def surface(page_id: str) -> JSONResponse:
        if page_id in AUTH_GATED_SURFACES:
            # Per-principal surface (e.g. /today): no signed identity, no projection.
            raise HTTPException(status_code=403, detail="surface requires a signed request")
        if page_id in DYNAMIC_SURFACES:
            return JSONResponse(_receipts_surface(store.list_receipts(20)))
        envelope = PUBLIC_SURFACES.get(page_id)
        if envelope is None:
            raise HTTPException(status_code=404, detail="unknown surface")
        return JSONResponse(envelope)

    @app.get("/.well-known/nanda-agent.json")
    def well_known() -> dict[str, object]:
        doc: dict[str, object] = {
            "agent_id": chapter_id,
            "did": server_did,
            "facts_url": f"{base_url}/.well-known/agent-facts.json",
            "a2a_url": f"{base_url}/api",
            "checkpoint": f"{base_url}/api/checkpoint",
            "registries": {},
            "protocol_versions": ["0.2", "0.3"],
        }
        if conformance_badge_doc is not None:
            doc["conformance"] = f"{base_url}/.well-known/conformance.json"
        if arp_badge_doc is not None:
            doc["arp_conformance"] = f"{base_url}/.well-known/arp-conformance.json"
        return doc

    @app.get("/.well-known/conformance.json")
    def conformance() -> JSONResponse:
        """The server's signed conformance badge — public, no auth, offline-verifiable."""
        if conformance_badge_doc is None:
            raise HTTPException(status_code=404, detail="no conformance badge published")
        return JSONResponse(conformance_badge_doc)

    @app.get("/.well-known/arp-conformance.json")
    def arp_conformance() -> JSONResponse:
        """The server's signed ARP receipt-suite badge — public, offline-verifiable."""
        if arp_badge_doc is None:
            raise HTTPException(status_code=404, detail="no ARP conformance badge published")
        return JSONResponse(arp_badge_doc)

    @app.get("/api/federation")
    def federation() -> dict[str, object]:
        # v0.1 is a solo, federation-ready server: no peers wired yet, shape is final.
        servers: dict[str, object] = {}
        return {
            "self": {"agent_id": chapter_id, "did": server_did},
            "chapters": servers,
            "total": len(servers),
        }

    @app.get("/api/federation/{peer_id}/members")
    def federation_members(peer_id: str) -> JSONResponse:
        if peer_id == chapter_id:
            members = store.list_members(1000)
            return JSONResponse(
                {
                    "chapter": peer_id,
                    "members": [{"agent_id": m.agent_id, "did_key": m.did_key} for m in members],
                    "total": len(members),
                }
            )
        raise HTTPException(status_code=404, detail=f"unknown peer: {peer_id}")

    return app


app = create_app()
