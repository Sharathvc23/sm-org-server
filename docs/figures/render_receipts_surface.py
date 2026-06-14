#!/usr/bin/env python3
"""Render the chapter's live `receipts` A2UI surface to a standalone HTML figure.

Not a mock: this spins up the chapter, emits real receipts (a member's via the
ingest endpoint + the chapter's own attestation via feedback), fetches the
actual `GET /api/surfaces/receipts` A2UI envelope, and renders its components.
The output is committed as docs/figures/receipts-surface.html.

    python docs/figures/render_receipts_surface.py
"""

from __future__ import annotations

import base64
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sm_arp import Identity, build_action, issue_receipt

from sm_server.app import create_app
from sm_server.signing import derive_did_key
from sm_server.store.sqlite import SqliteStore


def _seed_receipts(client: TestClient) -> None:
    alice = Identity.generate()
    for cat, summary in [
        ("data_shared", "Shared my calendar availability with the scheduling agent"),
        ("purchase", "Bought 2 tickets to the community meetup"),
        ("message_sent", "Answered a question in #introductions"),
    ]:
        action = build_action(category=cat, human_summary=summary)
        client.post("/api/receipts", json=issue_receipt(alice, principal_did=alice.did, action=action))

    # A chapter-emitted attestation, via a signed feedback request.
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    did, ts, body = derive_did_key(pub), str(int(time.time())), '{"kind":"intent_response_useful"}'
    sig = base64.b64encode(priv.sign(f"{body}:bob:{ts}".encode())).decode()
    client.post(
        "/api/feedback",
        content=body,
        headers={
            "X-Agent-ID": "bob",
            "X-Agent-DID-Key": did,
            "X-Agent-Sig-Scheme": "ed25519",
            "X-Agent-Timestamp": ts,
            "X-Agent-Signature": sig,
        },
    )


def _render(components: list[dict]) -> str:
    rows = []
    for c in components:
        if c.get("component") == "Heading":
            rows.append(f"<h1>{c['text']}</h1>")
        elif c.get("text") == "No receipts yet.":
            rows.append('<p class="empty">No receipts yet.</p>')
        else:
            when, _, rest = c.get("text", "").partition(" · ")
            cat, _, summary = rest.partition(" · ")
            rows.append(
                f'<div class="r"><span class="cat">{cat}</span>'
                f'<span class="sum">{summary}</span><time>{when}</time></div>'
            )
    body = "\n      ".join(rows)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Issuer Log — sm-server</title>
<style>
  body{{margin:0;background:#f1f5f9;font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#0f172a}}
  .card{{max-width:680px;margin:40px auto;background:#fff;border:1px solid #e2e8f0;border-radius:14px;
        box-shadow:0 1px 3px rgba(15,23,42,.06);overflow:hidden}}
  h1{{font-size:18px;margin:0;padding:18px 22px;border-bottom:1px solid #eef2f6}}
  .r{{display:grid;grid-template-columns:130px 1fr auto;gap:14px;align-items:center;
     padding:14px 22px;border-bottom:1px solid #f1f5f9}}
  .r:last-child{{border-bottom:0}}
  .cat{{font:600 11px ui-monospace,Menlo,monospace;color:#3730a3;background:#eef2ff;
       padding:3px 8px;border-radius:6px;justify-self:start}}
  .sum{{font-size:14px}} time{{font:11px ui-monospace,Menlo,monospace;color:#94a3b8}}
  .empty{{padding:22px;color:#94a3b8}}
  .cap{{max-width:680px;margin:0 auto 40px;color:#64748b;font-size:12.5px;text-align:center}}
</style></head>
<body>
  <div class="card">
      {body}
  </div>
  <p class="cap">Rendered from the live <code>GET /api/surfaces/receipts</code> A2UI envelope (v0.10).</p>
</body></html>
"""


def main() -> None:
    client = TestClient(create_app(store=SqliteStore(), chapter_id="demo-chapter"))
    _seed_receipts(client)
    envelope = client.get("/api/surfaces/receipts").json()
    html = _render(envelope["updateComponents"]["components"])
    out = Path(__file__).resolve().parent / "receipts-surface.html"
    out.write_text(html)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
