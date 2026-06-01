# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-06-01

Initial public release.

### Added
- Conformant chapter wire against a swappable `ChapterStore` interface:
  - `POST /api/members` — origin-gated registration with TOFU public key.
  - `POST /api/members/rotate` — signed, nonce-protected key rotation.
  - `POST /api/feedback` — signed-request verification (Ed25519, key-consistency, replay window) recording trust events.
  - `GET /api/agents/{id}/trust` — trust dossier (score, tier, history).
  - `GET /api/surfaces/{id}` — A2UI surface envelopes, public and auth-gated.
  - `GET /api/federation` and `GET /api/federation/{peer}/members` — federation overview and peer member views.
  - `GET /.well-known/nanda-agent.json` — peer discovery substrate.
- `SqliteStore` — zero-config, file-backed default backend with parameterized queries.
- Config-driven origin vocabulary (`CHAPTER_ORIGINS`, `CHAPTER_NONROTATABLE_ORIGINS`); no runtime-specific name in source.
- Trust ledger as the sum of canonical, server-set event deltas; tiers as thresholds.
- Signed conformance badge at `.nanda/conformance.json`.
