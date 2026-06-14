# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **ARP Issuer Log.** The chapter is now ARP-native — it keeps a verifiable log of [Agency Receipt Protocol](https://github.com/Sharathvc23/sm-arp) receipts via the `sm_arp` consumable library:
  - `POST /api/receipts` — verify (structure → signature → authority → per-issuer hash chain §6.4) and persist a signed receipt; nothing written on failure.
  - `GET /api/receipts/recent` (with `?principal=` filter) and `GET /api/receipts/{id}`.
  - A live `receipts` A2UI surface over the log.
  - Receipt persistence added to the `ChapterStore` seam, so it follows the chosen backend (e.g. Postgres), not a side file.
- **Chapter self-emission.** Recording feedback also signs a chapter `attestation_issued` receipt endorsing the member (`issuer=chapter → counterparty=member`). The chapter holds its own ARP identity (stable via `CHAPTER_SEED`, ephemeral otherwise).
- **Signed ARP conformance badge** at `.nanda/arp-conformance.json`, served at `GET /.well-known/arp-conformance.json` and advertised in the well-known doc. Generated mechanically by `scripts/gen_arp_badge.py` against the live ingest surface (`CHAPTER_ARP_BADGE_PATH` overrides).
- **Signed Merkle checkpoint** (`aae-checkpoint/0.1`) over the whole Issuer Log. The per-issuer hash chain proves *forward* tamper-evidence within an issuer; the checkpoint adds the *reverse* seam across the whole log — membership you can verify offline:
  - `GET /api/checkpoint` — an RFC 6962 Merkle root over every receipt (JCS-canonical leaf, including signature), signed by the chapter's ARP identity. Advertised in the well-known doc.
  - `GET /api/checkpoint/proof/{receipt_id}` — the inclusion proof for one receipt, taken over the same `(issued_at, receipt_id)` ordering as the root so leaf indices line up. A holder verifies membership against the signed root with no further chapter trust.
  - Pure RFC 6962 lib in `sm_server/merkle.py`, validated against independently-computed known answers; the checkpoint commits to the whole log (uncapped), never a silent prefix.

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
