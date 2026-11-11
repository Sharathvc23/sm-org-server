# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [0.2.0] — 2026-11-11

Security release closing the findings of the November 2026 audit, plus the
ARP Issuer Log, checkpoint and server rename that shipped on `main` after 0.1.0
without a release. Every fix is pinned by an in-repo test and the release passes
the umbrella server conformance suite (68 passed, 4 skipped, 0 failed against an
ephemeral instance; the 3 `requires_persistence` tests are deselected as in the
umbrella's own PR gate).

### Security
- **Registration hijack closed.** `POST /api/members` for an `agent_id` that
  already exists used to overwrite the stored public key (`INSERT OR REPLACE`),
  so anyone could take over any member by re-registering with their own key.
  An existing id now answers the *same* key with an idempotent `200` and any
  *other* key with `401 {"error": "key_mismatch"}`; the key of record changes
  only through `POST /api/members/rotate`. `public_key` is required and must be
  standard base64 of exactly 32 bytes (`400` otherwise); the `did_key` is
  derived server-side and a client-supplied one is ignored. A non-JSON or
  non-object body is `400`, not `500`.
- **Self-minted trust closed.** `POST /api/feedback` credited the *caller*
  `+1.0 intent_response_useful` on every call, ignoring the body — a member
  could reach the `core` tier alone in 75 requests. Feedback now credits the
  member named in `body["agent_id"]`, only when that member is registered and is
  not the caller, and at most once per `(voucher, subject, UTC day)`. Self-
  feedback, a missing subject or an unknown subject is still recorded (a
  receipt is issued) but mints nothing. The response gained `subject` and
  `credited` fields.
- **TOFU no longer invents an origin.** A first-contact signer was registered
  with origin `sovereign` even on deployments whose `SERVER_ORIGINS` admit no
  such origin. TOFU (spec §3.1) now applies only where `sovereign` is admitted;
  elsewhere an unknown signer is `401 no_stored_key` and registration is the
  only way in. v0.2 replay within the ±300 s window is still accepted, as the
  spec and the umbrella suite (R2) require — idempotency is the defence.
- **Issuer Log is append-only.** `append_receipt` was `INSERT OR REPLACE`: a
  valid receipt re-signed with the same `receipt_id` silently rewrote history.
  Re-posting a byte-identical receipt returns the existing `chain_link`; a
  different payload under an existing id is `409 {"error": "receipt_rewrite"}`;
  a second child of the same `(issuer_did, previous_receipt_hash)` is
  `409 {"error": "chain_fork"}`, also enforced by a unique index. A database
  that already contains a fork refuses to open with a clear message.
- **Rotation nonces are per agent.** The replay scope was chapter-wide
  (`consume_nonce(chapter_id, nonce)`), so any member could pre-burn a nonce
  another member was about to use. The scope is now `rotate:{agent_id}`, the
  nonce is consumed only after the old key's signature verifies, and
  `new_did_key` is derived from the new key rather than taken from the client.
  The §4.2 error strings are unchanged.
- **Garbage on file is `no_stored_key`, not a 500.** An undecodable stored
  public key used to raise inside the handler.

### Added
- **v0.3 signed requests** (`spec/0.3/signing.md`). `X-Agent-Sig-Scheme` is
  read and enforced: `ed25519` selects the v0.2 canonical string
  `{body}:{agent_id}:{timestamp}`; `ed25519+nonce` selects
  `{METHOD}:{url_path_with_query}:{body}:{agent_id}:{timestamp}:{nonce}` with
  `X-Agent-Nonce` (32 random bytes, standard base64) consumed per
  `(agent_id, nonce)`; any other value is `401 unknown_sig_scheme`. Every
  rejection is `401 {"error": <reason>, "detail": <reason>}` with the reason
  from the spec's closed set (`missing_agent_id`, `missing_signature`,
  `missing_timestamp`, `missing_nonce`, `unknown_sig_scheme`,
  `invalid_timestamp`, `expired_timestamp`, `invalid_did_key`, `key_mismatch`,
  `no_stored_key`, `nonce_replay`, `invalid_signature`). One verifier,
  `sm_server.auth.verify_signed_request`, is used by every protected route.
  Previously the scheme header was ignored and a v0.2 signature was accepted
  under `ed25519+nonce`.
- **Member directory gate** (spec §4.12). `GET /api/members` (and the
  trailing-slash form) and `GET /api/federation/{peer}/members` require a
  signed request; anonymous is `401`, and authorisation happens before peer
  resolution so an unknown peer does not leak as `404`. The directory envelope
  now carries `chapter` alongside `members` and `total`, with `total` equal to
  the number of members returned. A first-contact signer may TOFU-bootstrap on
  the directory read where the deployment admits `sovereign`.
- `GET /api/member/{agent_id}/profile` — the public exact-match lookup §4.12
  keeps open.
- `DELETE /api/members/{agent_id}` — a member removes itself with a signed
  request (no TOFU; another member's id is `403`). This is what lets the
  conformance suite clean up the identities it mints.
- **Server receipts are hash-chained.** Each receipt the server issues names
  the server's previous receipt as `previous_receipt_hash` (ARP §6.4); emission
  is serialised so two server actions cannot fork its chain.
  `ServerStore.last_receipt_for_issuer` supports this.
- `ServerStore.add_member` (insert-if-absent, atomic), `delete_member`,
  `last_receipt_for_issuer`, `close`; `ReceiptConflict` for append refusals.
- **Durable by default.** `SqliteStore()` and therefore
  `uvicorn sm_server.app:app` now open `SERVER_DB_PATH` (default
  `./sm-server.sqlite`) in WAL mode instead of `:memory:`, which lost every
  member, event and receipt on restart. `":memory:"` remains available for
  tests. Nonce rows older than 24 h are pruned on insert; databases created by
  0.1.0 are migrated in place.
- **Fail fast in production.** `SERVER_ENV=production` without `SERVER_SEED`
  refuses to start with an explanation (an ephemeral issuer identity orphans
  every receipt and checkpoint the server has signed). A malformed seed is
  refused in every environment.
- CI job that runs the umbrella server conformance suite against a booted
  instance when the `UMBRELLA_TOKEN` secret is present, and posts a notice
  instead of failing when it is not.

### Changed
- `GET /api/version` advertises `a2ui_versions: ["0.9", "0.10"]` with
  `preferred_a2ui_version: "0.10"` — the version every surface actually emits.
  It used to advertise only `0.9` while emitting `0.10`.
- `POST /api/members/rotate` also returns `new_did_key`.
- Feedback receipts: a credited vouch is `attestation_issued` with the
  *subject* as counterparty; an uncredited call is `attestation_received` with
  the caller as counterparty.
- **Server rename (Tier 4, brand only — wire frozen).** The package, prose,
  public symbols, and config use *server* vocabulary: `ChapterStore` →
  `ServerStore`, env vars `CHAPTER_*` → `SERVER_*` (legacy `CHAPTER_*` still
  read as aliases — no deployment breaks), app title `chapter-core` →
  `sm-org-server`. The **wire is unchanged**: `chapter_id`, the
  `ROTATE:{chapter_id}:…` canonical signing string, the `"chapter"`/
  `"chapters"` response keys, routes, and AgentFacts fields are all frozen by
  the protocol.
- README describes what the code does: the test count, the TOFU rule, and the
  replay model (v0.2 timestamp window only; v0.3 per-agent nonces).

### Removed
- `ServerStore.put_member` (upsert). Replaced by `add_member`; there is no
  path that overwrites a member's key other than rotation.

### Added earlier on `main` (unreleased until now)
- **ARP Issuer Log.** The server is ARP-native — it keeps a verifiable log of
  [Agency Receipt Protocol](https://github.com/Sharathvc23/sm-arp) receipts via
  the `sm_arp` library: `POST /api/receipts` (verify structure → signature →
  authority → per-issuer hash chain §6.4, then persist; nothing written on
  failure), `GET /api/receipts/recent` (with `?principal=`),
  `GET /api/receipts/{id}`, and a live `receipts` A2UI surface. Persistence is
  behind the `ServerStore` seam.
- **Server self-emission.** Recording feedback also signs a server receipt.
  The server holds its own ARP identity (stable via `SERVER_SEED`).
- **Signed ARP conformance badge** at `.nanda/arp-conformance.json`, served at
  `GET /.well-known/arp-conformance.json`, generated by
  `scripts/gen_arp_badge.py` (`SERVER_ARP_BADGE_PATH` overrides).
- **Signed Merkle checkpoint** (`aae-checkpoint/0.1`) over the whole Issuer
  Log: `GET /api/checkpoint` (RFC 6962 root, signed by the server) and
  `GET /api/checkpoint/proof/{receipt_id}` (inclusion proof over the same
  `(issued_at, receipt_id)` ordering). Pure RFC 6962 lib in
  `sm_server/merkle.py`.

## [0.1.0] — 2026-06-01

Initial public release.

### Added
- Conformant server wire against a swappable `ServerStore` interface:
  - `POST /api/members` — origin-gated registration with TOFU public key.
  - `POST /api/members/rotate` — signed, nonce-protected key rotation.
  - `POST /api/feedback` — signed-request verification (Ed25519, key-consistency, replay window) recording trust events.
  - `GET /api/agents/{id}/trust` — trust dossier (score, tier, history).
  - `GET /api/surfaces/{id}` — A2UI surface envelopes, public and auth-gated.
  - `GET /api/federation` and `GET /api/federation/{peer}/members` — federation overview and peer member views.
  - `GET /.well-known/nanda-agent.json` — peer discovery substrate.
- `SqliteStore` — zero-config, file-backed default backend with parameterized queries.
- Config-driven origin vocabulary (`SERVER_ORIGINS`, `SERVER_NONROTATABLE_ORIGINS`); no runtime-specific name in source.
- Trust ledger as the sum of canonical, server-set event deltas; tiers as thresholds.
- Signed conformance badge at `.nanda/conformance.json`.
