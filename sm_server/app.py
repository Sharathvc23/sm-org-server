"""The conformant protocol surface — minimal, backend-agnostic.

Implements exactly what `conformance/server/` requires of a server, against the
`ServerStore` interface. No LLM, no think-cycle, no specific database — the
agent's intelligence and governance live above this, as product or plugins.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import json
import os
import threading
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from sm_arp import Identity as ArpIdentity
from sm_arp import build_action, chain_link, issue_receipt, verify_receipt

from sm_server import merkle, signing, trust
from sm_server.auth import (
    TOFU_ORIGIN,
    SignedRequestError,
    decode_public_key,
    verify_signed_request,
)
from sm_server.store.base import Member, ReceiptConflict, ServerStore
from sm_server.store.sqlite import SqliteStore

ROTATION_WINDOW_S = 300

# Origin vocabulary is policy, not protocol: the core ships neutral and a deployment
# declares which origins it admits (and which may not self-rotate keys, e.g. managed
# install-time identities) via config. No runtime-specific name is baked into source.
DEFAULT_ORIGINS = (TOFU_ORIGIN,)

# The one trust event a member can earn through /api/feedback, and the only one a
# client can cause at all. Everything else in trust.EVENT_DELTAS is server-set.
FEEDBACK_EVENT = "intent_response_useful"

PROTOCOL_VERSIONS = ["0.2", "0.3"]
PREFERRED_PROTOCOL_VERSION = "0.3"
# Surfaces are emitted as v0.10 envelopes (`_surface` below); v0.9 is the
# previous major a renderer may still negotiate. Advertise what we emit.
A2UI_VERSIONS = ["0.9", "0.10"]
PREFERRED_A2UI_VERSION = "0.10"


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
        "version": PREFERRED_A2UI_VERSION,
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


async def _json_object(req: Request) -> dict[str, object] | JSONResponse:
    """The request body as a JSON object, or the 400 to send back instead."""
    try:
        body = await req.json()
    except (ValueError, UnicodeDecodeError):
        return JSONResponse({"error": "body is not valid JSON"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "body must be a JSON object"}, status_code=400)
    return body


def _server_identity() -> ArpIdentity:
    """The server's own ARP signing identity.

    Stable across restarts when ``SERVER_SEED`` (base64 of a 32-byte Ed25519
    seed) is set; ephemeral otherwise. A production deployment (``SERVER_ENV=
    production``) MUST set it — an ephemeral issuer makes every receipt and
    checkpoint the server signed unverifiable after the next restart.
    """
    seed_b64 = _env("SERVER_SEED", "CHAPTER_SEED")
    env = (_env("SERVER_ENV", "CHAPTER_ENV", default="") or "").strip().lower()
    if not seed_b64:
        if env == "production":
            raise RuntimeError(
                "SERVER_SEED is not set but SERVER_ENV=production. The server's ARP issuer "
                "identity would be regenerated on every restart, orphaning every receipt and "
                "checkpoint it has signed. Set SERVER_SEED to the standard base64 of a 32-byte "
                "Ed25519 seed, e.g. "
                "`python -c 'import os,base64;print(base64.b64encode(os.urandom(32)).decode())'`."
            )
        return ArpIdentity.generate()
    try:
        seed = base64.b64decode(seed_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RuntimeError("SERVER_SEED is not standard base64") from exc
    if len(seed) != 32:
        raise RuntimeError(f"SERVER_SEED must decode to 32 bytes, got {len(seed)}")
    identity: ArpIdentity = ArpIdentity.from_seed(seed)
    return identity


def create_app(
    store: ServerStore | None = None,
    chapter_id: str | None = None,
    origins: set[str] | None = None,
    nonrotatable_origins: set[str] | None = None,
) -> FastAPI:
    owns_store = store is None
    store = store or SqliteStore()
    # `chapter_id` is the frozen wire field (the server's identifier on the wire); the
    # env var that sets it is the new `SERVER_ID` (legacy `CHAPTER_ID` still honored).
    chapter_id = chapter_id or _env("SERVER_ID", "CHAPTER_ID", default="sm-org-server") or "sm-org-server"
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
    # TOFU (spec §3.1) records a first-contact signer as a self-custodied member.
    # A deployment that does not admit that origin gets no TOFU: an unknown
    # signer is `no_stored_key`, and registration is the only way in.
    tofu_allowed = TOFU_ORIGIN in valid_origins

    server_identity = _server_identity()
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

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield
        if owns_store:
            store.close()

    app = FastAPI(title="sm-org-server", lifespan=lifespan)

    @app.exception_handler(SignedRequestError)
    async def _signed_request_error(_req: Request, exc: SignedRequestError) -> JSONResponse:
        # spec/0.3/signing.md step 5: 401 with the closed-set reason. `detail`
        # mirrors `error` because v0.2 clients read the FastAPI-style key.
        return JSONResponse({"error": exc.reason, "detail": exc.reason}, status_code=401)

    # The server's own chain: a receipt links to the server's previous one, and
    # two server actions must not race into a fork, so emission is serialised.
    emit_lock = threading.Lock()

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
        member's do, hash-chained to its previous receipt (ARP §6.4) so the
        server's own log is as tamper-evident as anyone else's.
        """
        action = build_action(
            category=category,
            human_summary=human_summary,
            counterparty_did=counterparty_did,
            counterparty_label=counterparty_label,
        )
        with emit_lock:
            last = store.last_receipt_for_issuer(server_did)
            receipt: dict[str, object] = issue_receipt(
                server_identity,
                principal_did=principal_did,
                action=action,
                previous_receipt_hash=chain_link(last) if last is not None else None,
            )
            store.append_receipt(receipt)
        return receipt

    def directory_envelope(members: list[Member]) -> dict[str, object]:
        return {
            "chapter": chapter_id,
            "members": [
                {"agent_id": m.agent_id, "name": m.name, "origin": m.origin, "did_key": m.did_key}
                for m in members
            ],
            "total": len(members),
        }

    @app.get("/health")
    def health() -> dict[str, object]:
        return {"status": "ok", "agent_id": chapter_id, "members": store.member_count(), "federation": 0}

    @app.get("/api/version")
    def version() -> dict[str, object]:
        return {
            "chapter_id": chapter_id,
            "protocol_versions": list(PROTOCOL_VERSIONS),
            "preferred_version": PREFERRED_PROTOCOL_VERSION,
            "a2ui_versions": list(A2UI_VERSIONS),
            "preferred_a2ui_version": PREFERRED_A2UI_VERSION,
        }

    @app.post("/api/members")
    async def register(req: Request) -> JSONResponse:
        body = await _json_object(req)
        if isinstance(body, JSONResponse):
            return body
        agent_id, name = body.get("agent_id"), body.get("name")
        if not (isinstance(agent_id, str) and agent_id and isinstance(name, str) and name):
            return JSONResponse({"error": "agent_id and name required"}, status_code=400)
        origin = body.get("origin")
        if not isinstance(origin, str) or origin not in valid_origins:
            return JSONResponse(
                {"error": f"invalid origin: must be one of {sorted(valid_origins)}"},
                status_code=200,
            )
        public_key = body.get("public_key")
        raw_key = decode_public_key(public_key) if isinstance(public_key, str) else None
        if raw_key is None:
            return JSONResponse(
                {"error": "public_key required: standard base64 of a 32-byte Ed25519 public key"},
                status_code=400,
            )
        # Store the canonical encoding and derive the did:key ourselves — a client
        # does not get to assert what its key decodes to.
        public_key_b64 = base64.b64encode(raw_key).decode()
        did_key = signing.derive_did_key(raw_key)
        existing = store.get_member(agent_id)
        if existing is not None and existing.origin != origin:
            return JSONResponse(
                {"error": "origin mismatch", "existing_origin": existing.origin}, status_code=200
            )
        if existing is None and store.add_member(Member(agent_id, name, origin, public_key_b64, did_key)):
            return JSONResponse(
                {"agent_id": agent_id, "registered": True, "chapter": chapter_id, "origin": origin}
            )
        # Taken (before this request, or by one that raced it). The id belongs to
        # whoever holds the key of record; the same key is an idempotent re-register,
        # any other key is an attempted takeover. Rotation is the only key change.
        existing = existing or store.get_member(agent_id)
        if existing is None or decode_public_key(existing.public_key) != raw_key:
            return JSONResponse({"error": "key_mismatch", "detail": "key_mismatch"}, status_code=401)
        return JSONResponse(
            {"agent_id": agent_id, "registered": True, "chapter": chapter_id, "origin": existing.origin}
        )

    @app.post("/api/members/rotate")
    async def rotate(req: Request) -> JSONResponse:
        a = await _json_object(req)
        if isinstance(a, JSONResponse):
            return a
        agent_id = a.get("agent_id")
        member = store.get_member(agent_id) if isinstance(agent_id, str) else None
        if member is None or not isinstance(agent_id, str):
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
            if not isinstance(ts, int | str) or abs(int(time.time()) - int(ts)) > ROTATION_WINDOW_S:
                return JSONResponse({"error": f"timestamp out of window (max {ROTATION_WINDOW_S}s)"})
        except ValueError:
            return JSONResponse({"error": f"timestamp out of window (max {ROTATION_WINDOW_S}s)"})
        new_pk_b64 = a.get("new_public_key_b64")
        new_raw = decode_public_key(new_pk_b64) if isinstance(new_pk_b64, str) else None
        if new_raw is None:
            return JSONResponse(
                {"error": "new pubkey wrong length (Ed25519 needs 32 bytes, standard base64)"}
            )
        if new_raw == decode_public_key(member.public_key):
            return JSONResponse({"error": "new public key must differ from old"})
        nonce = a.get("nonce")
        if not isinstance(nonce, str) or not nonce:
            return JSONResponse({"error": "nonce required"})
        signature = a.get("signature")
        old_raw = decode_public_key(member.public_key)
        canonical = f"ROTATE:{chapter_id}:{agent_id}:{new_pk_b64}:{ts}:{nonce}"
        try:
            sig = base64.b64decode(signature, validate=True) if isinstance(signature, str) else b""
        except (binascii.Error, ValueError):
            sig = b""
        if old_raw is None or not signing.verify(old_raw, sig, canonical.encode()):
            return JSONResponse({"error": "invalid signature (old key did not sign this attestation)"})
        # Scoped per agent: one member cannot pre-burn another's nonce. Consumed
        # only after the old key has proven it signed this attestation.
        if not store.consume_nonce(f"rotate:{agent_id}", nonce):
            return JSONResponse({"error": "nonce replay"})
        # The did:key is derived from the key, never taken from the client.
        new_did = signing.derive_did_key(new_raw)
        store.rotate_key(agent_id, base64.b64encode(new_raw).decode(), new_did)
        return JSONResponse(
            {"agent_id": agent_id, "rotated": True, "new_public_key_b64": new_pk_b64, "new_did_key": new_did}
        )

    async def directory(req: Request, limit: int) -> JSONResponse:
        # §4.12: the directory is for members, not for anonymous bulk enumeration.
        # A first-contact signer MAY bootstrap here (TOFU) where the deployment allows it.
        verify_signed_request(req, await req.body(), store, tofu=tofu_allowed)
        return JSONResponse(directory_envelope(store.list_members(limit)))

    @app.get("/api/members")
    async def list_members(req: Request, limit: int = 50) -> JSONResponse:
        return await directory(req, limit)

    @app.get("/api/members/", include_in_schema=False)
    async def list_members_slash(req: Request, limit: int = 50) -> JSONResponse:
        # Explicit, so the trailing-slash form is gated too instead of 307-ing.
        return await directory(req, limit)

    @app.get("/api/member/{agent_id}/profile")
    def member_profile(agent_id: str) -> JSONResponse:
        # §4.12 exact-match lookup stays open: a pasted profile link renders without an account.
        m = store.get_member(agent_id)
        if m is None:
            raise HTTPException(status_code=404, detail="unknown agent")
        return JSONResponse(
            {
                "agent_id": m.agent_id,
                "name": m.name,
                "origin": m.origin,
                "did_key": m.did_key,
                "chapter": chapter_id,
            }
        )

    @app.delete("/api/members/{agent_id}")
    async def delete_member(agent_id: str, req: Request) -> JSONResponse:
        """A member removes its own membership — self-signed, no TOFU (nothing to bootstrap)."""
        raw = await req.body()
        if store.get_member(agent_id) is None:
            raise HTTPException(status_code=404, detail="unknown agent")
        signer = verify_signed_request(req, raw, store, tofu=False)
        if signer.agent_id != agent_id:
            raise HTTPException(status_code=403, detail="a member may only delete itself")
        store.delete_member(agent_id)
        return JSONResponse({"agent_id": agent_id, "deleted": True})

    @app.post("/api/feedback")
    async def feedback(req: Request) -> JSONResponse:
        # The body is signed verbatim, so verify the raw bytes — re-serialising
        # would change the canonical string.
        raw = await req.body()
        signer = verify_signed_request(req, raw, store, tofu=tofu_allowed)
        caller = signer.agent_id

        try:
            parsed = json.loads(raw) if raw else {}
        except ValueError:
            parsed = {}
        subject = parsed.get("agent_id") if isinstance(parsed, dict) else None
        subject = subject if isinstance(subject, str) and subject else None

        # Trust is something another member says about you. The caller names a
        # subject; the subject must be a registered member other than the caller;
        # and one voucher moves one subject at most once per UTC day. Anything
        # else is still a recorded interaction — it just mints nothing.
        credited = False
        subject_member = store.get_member(subject) if subject is not None and subject != caller else None
        if subject is not None and subject_member is not None:
            today = dt.datetime.now(dt.UTC).date().isoformat()
            if store.consume_nonce(f"vouch:{caller}:{subject}", today):
                store.record_trust_event(subject, FEEDBACK_EVENT, trust.EVENT_DELTAS[FEEDBACK_EVENT])
                credited = True

        if credited and subject_member is not None:
            receipt = emit_server_receipt(
                server_did,
                category="attestation_issued",
                human_summary=f"Recorded {caller}'s positive feedback on {subject}"[:280],
                counterparty_did=subject_member.did_key,
                counterparty_label=subject,
            )
        else:
            receipt = emit_server_receipt(
                server_did,
                category="attestation_received",
                human_summary=f"Received feedback from member {caller}"[:280],
                counterparty_did=signer.did_key,
                counterparty_label=caller,
            )
        return JSONResponse(
            {
                "recorded": True,
                "agent_id": caller,
                "subject": subject,
                "credited": credited,
                "receipt_id": receipt["receipt_id"],
            }
        )

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
        verification; on failure nothing is written. The log is append-only:
        a rewrite or a chain fork is refused with 409.
        """
        receipt = await _json_object(req)
        if isinstance(receipt, JSONResponse):
            return receipt

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

        try:
            link = store.append_receipt(receipt)
        except ReceiptConflict as exc:
            return JSONResponse({"error": exc.reason, "receipt_id": receipt["receipt_id"]}, status_code=409)
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
            "protocol_versions": list(PROTOCOL_VERSIONS),
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
        # A solo, federation-ready server: no peers wired yet, shape is final.
        servers: dict[str, object] = {}
        return {
            "self": {"agent_id": chapter_id, "did": server_did},
            "chapters": servers,
            "total": len(servers),
        }

    @app.get("/api/federation/{peer_id}/members")
    async def federation_members(peer_id: str, req: Request) -> JSONResponse:
        # Authorisation before peer resolution: an anonymous caller learns neither
        # the members nor which peers exist (§4.12).
        verify_signed_request(req, await req.body(), store, tofu=tofu_allowed)
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
