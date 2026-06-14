# Governance

## Scope

`sm-server` is the minimal conformant wire of a chapter server: registration, key rotation, signed feedback, the trust ledger, surfaces, federation discovery, and the well-known substrate. It is deliberately *not* an agent runtime, a database, or a product. Storage backends, origin policy, and agent behaviour live above this line, in your code.

## Versioning

- The package follows semantic versioning, independent of any protocol version.
- The **protocol wire** it implements — canonical signing strings, did:key derivation, trust-event deltas, the A2UI envelope shape — does not change within a major. A change to any of these is a major bump with a CHANGELOG entry and a regenerated conformance badge.
- Additive, namespaced, or configuration-only changes are minor or patch.

## Conformance

A build is conformant *iff* a conformance suite passes against a running instance and the repository carries a green, signed `.nanda/conformance.json` pinned to that suite's vector digest. A passing badge is a precondition for any release tag. The signing key is a runtime key held outside CI; it is never committed.

## Contributions

Issues and pull requests are welcome. A change that touches the wire must keep conformance green and update the badge. A change that touches storage or policy must keep the `ChapterStore` Protocol stable or version it explicitly. All code keeps the gate green: `ruff`, `mypy --strict`, and `pytest` at or above the coverage floor.

## Attribution

Personal research contributions aligned with [Project NANDA](https://projectnanda.org) standards. Maintained by [stellarminds.ai](https://stellarminds.ai).
