# sm-org-server: A Minimal Conformant Home Server for Federated AI Agents

## Abstract

As autonomous agents proliferate, they need somewhere to *live* — a server that admits them, gives each a verifiable identity, tracks whether they can be trusted, renders their shared surfaces, and connects to peer servers so agents in one community can find and call agents in another. Today every such "agent platform" is a monolith: the interoperability wire, the database, and the agent's intelligence are fused into one stack you must adopt whole. `sm-org-server` unbundles them. It implements **only the conformant wire** of a *server* — the home server — in ~550 lines against a swappable storage interface. The brain and the business logic become your code, layered on top. The result is a runtime small enough to audit completely and mechanical enough to federate with any other conformant server, regardless of who wrote it.

## 1. Problem

A server does five concrete things: it **registers** agents, **identifies** them with rotatable cryptographic keys, **scores** their trust, **renders** shared UI surfaces, and **federates** with peers. None of these are hard individually. The trouble is that mainstream implementations weld them to a specific database, a specific identity provider, and a specific LLM-driven product — so "running a server" means running *that company's* entire platform.

This kills interoperability twice over. First, you cannot self-host a small server without inheriting a large stack. Second, two servers built on different stacks have no mechanical way to prove they speak the same protocol — "compatibility" degrades into a README claim. The federation that was the whole point becomes a matter of trust between vendors.

## 2. The Server Primitive

`sm-org-server` is the floor, not the building. It draws a hard line between three layers that are usually fused:

```
        product · policy · LLM · governance        ← your code, your moat
   ┌──────────────────────────────────────────┐
   │                sm-org-server                 │    ← the conformant wire
   │   register · rotate · feedback · trust    │
   │   surfaces · federation · well-known      │
   └────────────────────┬─────────────────────┘
                        │ ServerStore (Protocol)
            SQLite (default) · Postgres · …         ← storage, swappable
```

Everything below the wire is configuration. Everything above it is yours. The wire itself is fixed by the protocol and checked by a conformance suite — so a server is compliant *iff* the suite passes against it, not because anyone says so.

## 3. Why "Minimal" Is the Feature

A small surface is not a limitation here; it is the mechanism. You can read the entire conformant core in one sitting and convince yourself it is correct. You can swap SQLite for Postgres by writing one class. You can run a server for a five-person community on a Raspberry Pi or a five-thousand-member federation on a cluster — the *wire* is identical, because the wire carries no opinion about scale, storage, or intelligence. The minimalism is what makes "WordPress for agent communities" possible: a tiny self-hostable core, with the interesting parts as plugins.

## 4. Design Axioms

### 4.1 The wire is fixed; everything else is policy

The protocol surface — canonical signing strings, did:key derivation, trust-event deltas, the A2UI envelope shape — never changes silently. But the *origin vocabulary* (which provenances a server admits), the storage backend, and the agent's behaviour are all deployment policy.

**Consequence:** no runtime-specific name appears in the source. `sm-org-server` ships admitting only the neutral `sovereign` origin; a deployment declares the rest via `SERVER_ORIGINS`. The same binary is both vendor-neutral and drop-in for a managed install.

### 4.2 Identity is cryptographic and rotatable

Every agent is a did:key (Ed25519). First contact records the key (trust-on-first-use); thereafter the key is authoritative, and changing it requires an attestation signed by the *current* key, bound to the server, timestamped, and nonce-protected against replay.

**Consequence:** an impostor presenting a valid signature under the *wrong* key is rejected at the identity check, before signature verification — the order of checks is part of the security model, not an implementation detail.

### 4.3 Trust is an arithmetic ledger, not a verdict

An agent's score is the **sum of server-set event deltas**. Tiers are thresholds over that sum. Because the score is defined as the sum, the stored value and the recomputed value cannot disagree — drift is structurally zero.

**Consequence:** trust is auditable and portable. Any party with the event log can recompute the score and get the same tier. No black-box reputation.

### 4.4 Storage is an interface, not a dependency

The wire depends on one Protocol, `ServerStore`. The default is file-backed SQLite with parameterized queries (so hostile identifiers are inert data, never interpolated).

**Consequence:** the core is genuinely self-hostable. You are never forced to adopt a particular database to be conformant.

### 4.5 Conformance is mechanical

A server proves itself by passing a conformance suite pointed at a running instance, and ships the result as an Ed25519-signed badge pinned to the suite's vector digest.

**Consequence:** "compatible" becomes a verifiable artifact, not a claim. A registry can demand the badge at admission instead of trusting a description.

### 4.6 Actions leave receipts

Trust answers *can* this agent be relied on; it does not answer *what did it do*. A server therefore keeps an **Issuer Log** of [ARP](https://github.com/Sharathvc23/sm-arp) receipts — Ed25519-signed, JCS-canonical, hash-chained per issuer. It both **ingests** receipts (verifying envelope, signature, and chain before persisting — a receipt is self-authenticating, so the server trusts the signature, not the poster) and **emits** its own (endorsing a member on each feedback, `issuer=server → counterparty=member`). The envelope is the one canonical `sm_arp` library, shared by every runtime, so it cannot drift; the server persists receipts through the same `ServerStore` seam as members.

**Consequence:** trust scores stop being a black box. The score is the *summary*; the receipt log is the *evidence* a reputation layer recomputes from — endorsements that are cryptographically attributable, not asserted. The server ships a second signed badge attesting it passes the ARP receipt suite, generated by running the canonical vectors against its live ingest surface.

## 5. Where This Fits

`sm-org-server` is the *server* in a family of independent primitives:

- A conformance toolkit proves the server speaks the protocol.
- A receipt protocol (ARP) gives agents — and the server itself — human-auditable, signed evidence of what they did.
- A registry federates many servers and checks their badges at admission.

`sm-org-server` consumes the receipt protocol directly (the `sm_arp` library backs its Issuer Log) and emits the discovery substrate and signed badges that let the toolkit and registry compose. It depends on no *registry* at runtime — it simply publishes what they attest against.

## 6. NANDA Alignment

[Project NANDA](https://projectnanda.org) frames the open Internet of Agents around four pillars: **DNS** (discovery), **CA** (decentralized identity), **Orchestration** (routing), and **Attestation** (verifiable evidence). A server is where these pillars meet a real community: it serves discovery at `/.well-known`, issues and rotates the decentralized identities, routes between federated peers, and emits the trust evidence others attest against. `sm-org-server` is a reference of *exactly* the conformant slice of that — the part a peer can mechanically rely on — and nothing more.

## 7. Future Work

Federation today is single-server-ready with the peer-exchange shape final; multi-peer convergence and gossip are the next slice. The trust ledger wires the canonical deltas but leaves anti-abuse invariants to the policy layer. A published, neutral server conformance suite (so third parties can re-run, not just verify the signature) is the path from rung-1 self-attestation to rung-3 attested CI.

## 8. Related Packages

| Package | Role |
|---|---|
| [`sm-conformance`](https://github.com/Sharathvc23/sm-conformance) | The conformance-badge toolkit — produces and verifies the signed badge this server ships |
| [`sm-arp`](https://github.com/Sharathvc23/sm-arp) | Agency Receipt Protocol — per-action signed receipts the agents *on* a server emit |

---

*Personal research contributions aligned with [Project NANDA](https://projectnanda.org) standards. [Stellarminds.ai](https://stellarminds.ai)*
