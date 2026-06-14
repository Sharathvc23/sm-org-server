#!/usr/bin/env python3
"""Generate sm-server's signed ARP conformance badge — mechanically.

Conformance is a *run*, not a declaration: this drives the live chapter's
ingest surface with the canonical ARP receipt vector corpus and counts what it
actually accepts/rejects, then signs the result with the chapter's runtime key
via sm-conformance's badge primitive (rung 1, self-signed).

    pip install 'sm-arp[conformance]'           # brings in sm-conformance
    ARP_REPO=~/sm-arp \
    NANDA_RUNTIME_KEY=~/.config/nanda-runtime-keys/chapter.hex \
        python scripts/gen_arp_badge.py

The ARP vector corpus + badge tool live in the sm-arp repo (they are not shipped
in its wheel), so point ARP_REPO at a checkout. The signing key is a 32-byte
Ed25519 seed in hex; it is never committed. Writes .nanda/arp-conformance.json.
"""

from __future__ import annotations

import binascii
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from sm_server.app import create_app
from sm_server.store.sqlite import SqliteStore

ARP_REPO = Path(os.environ.get("ARP_REPO", str(Path.home() / "sm-arp"))).expanduser()
sys.path.insert(0, str(ARP_REPO))  # for conformance.arp.badge + its vectors/schema

from conformance.arp.badge import build_arp_badge  # noqa: E402

VECTORS = ARP_REPO / "vectors" / "arp" / "0.1"


def _expected_accept(vector: dict) -> bool:
    return vector["expected_outcome"] == "verify_pass"


def run_corpus(client: TestClient) -> tuple[int, int, int]:
    """POST each vector to /api/receipts (genesis before linked, via filename
    order) and tally accept-vs-reject against each vector's documented verdict."""
    passed = failed = skipped = 0
    for path in sorted(VECTORS.glob("*.json")):
        vector = json.loads(path.read_text())
        resp = client.post("/api/receipts", json=vector["receipt"])
        accepted = resp.status_code == 200 and resp.json().get("accepted") is True
        if accepted is _expected_accept(vector):
            passed += 1
        else:
            failed += 1
            print(f"  MISMATCH {path.name}: expected accept={_expected_accept(vector)}, got {accepted}")
    return passed, failed, skipped


def main() -> int:
    key_path = Path(
        os.environ.get("NANDA_RUNTIME_KEY", str(Path.home() / ".config/nanda-runtime-keys/chapter.hex"))
    ).expanduser()
    seed = binascii.unhexlify(key_path.read_text().strip())

    client = TestClient(create_app(store=SqliteStore()))
    passed, failed, skipped = run_corpus(client)
    print(f"ARP corpus: {passed} passed, {failed} failed, {skipped} skipped")

    badge = build_arp_badge(
        "sm-server",
        passed=passed,
        failed=failed,
        skipped=skipped,
        signing_key32=seed,
        signed_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S+00:00"),
    )
    out = Path(__file__).resolve().parent.parent / ".nanda" / "arp-conformance.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(badge, indent=2) + "\n")
    print(f"wrote {out} (signed_by {badge['signed_by']})")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
