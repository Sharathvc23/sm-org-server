"""Signed-request verification — the one gate every protected route goes through.

Implements ``spec/0.2/signing.md`` (scheme ``ed25519``) and ``spec/0.3/signing.md``
(scheme ``ed25519+nonce``) over the headers a request carries:

    v0.2 canonical = f"{body}:{agent_id}:{timestamp}"
    v0.3 canonical = f"{METHOD}:{url_path_with_query}:{body}:{agent_id}:{timestamp}:{nonce}"

Every rejection is a :class:`SignedRequestError` whose ``reason`` is drawn from
the spec's closed set, so a client can act on it and an auditor can filter on
it. The HTTP layer maps the error to ``401 {"error": reason, "detail": reason}``.

TOFU (§3.1) is the caller's decision, not this module's: a route that admits a
first-contact signer passes ``tofu=True`` and the presented did:key becomes the
key of record; a route that must not (rotation, self-delete) passes ``False``
and an unknown signer is ``no_stored_key``.
"""

from __future__ import annotations

import base64
import binascii
import time
from dataclasses import dataclass

from fastapi import Request

from sm_server import signing
from sm_server.store.base import Member, ServerStore

SIGNED_REQUEST_WINDOW_S = 300
NONCE_BYTES = 32

SCHEME_V02 = "ed25519"
SCHEME_V03 = "ed25519+nonce"

# The origin recorded for an identity the server first met as a signer. TOFU
# is by definition self-custodied: nobody vouched for the key but its holder.
TOFU_ORIGIN = "sovereign"

# spec/0.3/signing.md §"What the chapter does" step 5 — the closed set.
REASONS: frozenset[str] = frozenset(
    {
        "missing_agent_id",
        "missing_signature",
        "missing_timestamp",
        "missing_nonce",
        "unknown_sig_scheme",
        "invalid_timestamp",
        "expired_timestamp",
        "invalid_did_key",
        "key_mismatch",
        "no_stored_key",
        "nonce_replay",
        "invalid_signature",
    }
)


class SignedRequestError(Exception):
    """A signed request failed verification for exactly one closed-set reason."""

    def __init__(self, reason: str) -> None:
        if reason not in REASONS:
            raise ValueError(f"not a spec reason: {reason!r}")
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class VerifiedSigner:
    """Who signed, with what key, and whether this request bootstrapped them."""

    agent_id: str
    public_key: bytes
    did_key: str
    member: Member
    scheme: str
    tofu_registered: bool


def decode_public_key(b64: str) -> bytes | None:
    """Standard-base64 → 32 raw Ed25519 bytes, or None if it is not exactly that."""
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError, TypeError):
        return None
    return raw if len(raw) == NONCE_BYTES else None


def _decode_nonce(b64: str) -> bool:
    try:
        return len(base64.b64decode(b64, validate=True)) == NONCE_BYTES
    except (binascii.Error, ValueError, TypeError):
        return False


def url_path_with_query(request: Request) -> str:
    """The request-line path plus query string — what a v0.3 client binds."""
    path = request.url.path
    query = request.scope.get("query_string", b"")
    if query:
        return f"{path}?{query.decode('latin-1')}"
    return path


def verify_signed_request(
    request: Request,
    raw_body: bytes,
    store: ServerStore,
    tofu: bool,
) -> VerifiedSigner:
    """Verify a signed request against the member's key of record.

    Raises :class:`SignedRequestError` on any failure; never returns a
    partially-verified signer. On success with ``tofu=True`` and an unknown
    ``agent_id``, the presented key has been recorded as that agent's key.
    """
    h = request.headers
    agent_id = h.get("x-agent-id")
    if not agent_id:
        raise SignedRequestError("missing_agent_id")
    sig_b64 = h.get("x-agent-signature")
    if not sig_b64:
        raise SignedRequestError("missing_signature")
    ts = h.get("x-agent-timestamp")
    if not ts:
        raise SignedRequestError("missing_timestamp")
    scheme = h.get("x-agent-sig-scheme")
    if scheme not in (SCHEME_V02, SCHEME_V03):
        raise SignedRequestError("unknown_sig_scheme")
    nonce = h.get("x-agent-nonce")
    if scheme == SCHEME_V03 and not (nonce and _decode_nonce(nonce)):
        # A nonce that is not 32 random bytes is not a nonce — spec §Headers.
        raise SignedRequestError("missing_nonce")

    try:
        ts_int = int(ts)
    except ValueError:
        raise SignedRequestError("invalid_timestamp") from None
    if abs(int(time.time()) - ts_int) > SIGNED_REQUEST_WINDOW_S:
        raise SignedRequestError("expired_timestamp")

    did_key_hdr = h.get("x-agent-did-key")
    if not did_key_hdr:
        raise SignedRequestError("invalid_did_key")
    try:
        claimed_pub = signing.parse_did_key(did_key_hdr)
    except ValueError:
        raise SignedRequestError("invalid_did_key") from None
    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except (binascii.Error, ValueError):
        raise SignedRequestError("invalid_signature") from None

    member = store.get_member(agent_id)
    if member is not None:
        # Garbage on file is "no key", never a 500 — and never a match.
        stored = decode_public_key(member.public_key)
        if stored is None:
            raise SignedRequestError("no_stored_key")
        if claimed_pub != stored:
            raise SignedRequestError("key_mismatch")
    elif not tofu:
        raise SignedRequestError("no_stored_key")

    try:
        body = raw_body.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise SignedRequestError("invalid_signature") from None
    if scheme == SCHEME_V03:
        canonical = f"{request.method.upper()}:{url_path_with_query(request)}:{body}:{agent_id}:{ts}:{nonce}"
    else:
        canonical = f"{body}:{agent_id}:{ts}"
    if not signing.verify(claimed_pub, sig, canonical.encode("utf-8")):
        raise SignedRequestError("invalid_signature")

    # Consume the nonce only after the signature verifies, so nobody can burn
    # another agent's nonces without holding their key. Scoped per agent (§Replay).
    if scheme == SCHEME_V03 and nonce is not None and not store.consume_nonce(agent_id, nonce):
        raise SignedRequestError("nonce_replay")

    tofu_registered = False
    if member is None:
        member = Member(
            agent_id,
            agent_id,
            TOFU_ORIGIN,
            base64.b64encode(claimed_pub).decode(),
            signing.derive_did_key(claimed_pub),
        )
        tofu_registered = store.add_member(member)
        if not tofu_registered:
            # Lost a race with another first-contact request for this id: the
            # key that landed is the key of record, and this one must match it.
            landed = store.get_member(agent_id)
            if landed is None or decode_public_key(landed.public_key) != claimed_pub:
                raise SignedRequestError("key_mismatch")
            member = landed

    return VerifiedSigner(
        agent_id=agent_id,
        public_key=claimed_pub,
        did_key=member.did_key,
        member=member,
        scheme=scheme,
        tofu_registered=tofu_registered,
    )
