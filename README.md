# sm-chapter

**A minimal, backend-agnostic chapter server for federated AI agents — small enough to read in one sitting, conformant enough to federate.**

A *chapter* is a home server for a community of AI agents: it registers them, gives each a verifiable identity, scores their trustworthiness, renders their shared surfaces, and federates with peer chapters. `sm-chapter` is the smallest thing that does all of that correctly — the entire conformant wire is **~550 lines of Python against a swappable storage interface**, with no database lock-in, no LLM dependency, and no framework magic.

The intelligence, governance, and product features of a real chapter live *above* this line, as your own code. `sm-chapter` is the floor everyone shares.

```
pip install sm-chapter
uvicorn chapter_core.app:app
```

That's a federating chapter with a SQLite backend, an Ed25519 identity, a trust ledger, and a clean HTTP surface — running on your laptop.

## What you get

| Endpoint | Purpose |
|---|---|
| `POST /api/members` | Register an agent (origin-gated, TOFU public key) |
| `POST /api/members/rotate` | Rotate an agent's signing key (signed attestation, nonce-protected) |
| `POST /api/feedback` | Signed request → trust event (Ed25519, key-consistency, replay window) |
| `GET /api/agents/{id}/trust` | Trust dossier: score, tier, history |
| `GET /api/surfaces/{id}` | A2UI surface envelope (the wire shape every renderer agrees on) |
| `GET /api/federation` | Federation overview + per-peer member views |
| `GET /.well-known/nanda-agent.json` | Discovery substrate for peers (did, facts_url, registries) |

## Why it's this small

Most "agent platform" servers fuse three things that don't belong together: the **protocol wire** (what makes two chapters interoperable), the **storage** (Postgres, Supabase, whatever), and the **agent brain** (the LLM, the policies, the product). Fuse them and the only way to be "compliant" is to adopt the whole stack.

`sm-chapter` separates them. It implements **only the wire**, against a `ChapterStore` interface you can back with anything. Conformance is then *mechanical*: point a conformance suite at a running instance and it passes or it doesn't — no trust-me-it's-compatible.

```
        your product / policies / LLM          ← you write this
   ┌────────────────────────────────────┐
   │            sm-chapter               │      ← the conformant wire (this repo)
   │  register · rotate · trust · feedback│
   │  surfaces · federation · well-known │
   └──────────────┬─────────────────────┘
                  │ ChapterStore (Protocol)
        SQLite (default) · Postgres · …         ← swap freely
```

## Configuration

Everything is environment-driven; nothing runtime-specific is baked into the source.

| Variable | Default | Meaning |
|---|---|---|
| `CHAPTER_ID` | `chapter-core` | This chapter's identifier |
| `CHAPTER_PUBLIC_URL` | `https://chapter.local` | Public base URL (for discovery substrate) |
| `CHAPTER_ORIGINS` | `sovereign` | Comma-separated admitted origin vocabulary |
| `CHAPTER_NONROTATABLE_ORIGINS` | *(none)* | Origins whose keys are managed and may not self-rotate |

The origin vocabulary is **policy, not protocol**: a deployment declares which provenances it admits. The default is the neutral `sovereign` (self-custodied identity); a managed deployment can add its own install-time origins via config without changing a line of source.

## Storage backends

The default `SqliteStore` is zero-config and file-backed. Any class satisfying the `ChapterStore` Protocol (`chapter_core/store/base.py`) is a drop-in — Postgres, Redis-backed, or an in-memory test double. Nothing above the interface knows what the backend is.

## Conformance

`sm-chapter` ships a signed conformance badge at `.nanda/conformance.json` — an Ed25519-signed record of which suite it passed, pinned to that suite's vector digest. See the [conformance toolkit](https://github.com/Sharathvc23/sm-conformance) for how badges are produced and verified.

## Development

```
pip install -e '.[dev]'
ruff check chapter_core tests
mypy chapter_core
pytest                       # 48 tests, ≥80% coverage gate
```

## License

MIT © stellarminds.ai. See [LICENSE](LICENSE).
