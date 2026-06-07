"""SQLite-backed receipt log.

The **Issuer Log** (spec §10.2) and the **Agency Log** (§10.1) are the same
store seen from two vantage points — one keeps the receipts an issuer accepted,
the other the receipts a principal's own agent produced. Both are
``ReceiptLog``; ``IssuerLog`` / ``AgencyLog`` are aliases so call sites read in
the right voice.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .receipts import chain_link


class ReceiptLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS receipts (
                    receipt_id   TEXT NOT NULL,
                    issuer_did   TEXT NOT NULL,
                    principal_did TEXT NOT NULL,
                    issued_at    TEXT NOT NULL,
                    category     TEXT,
                    counterparty_did TEXT,
                    previous_receipt_hash TEXT,
                    chain_link   TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    PRIMARY KEY (issuer_did, receipt_id)
                )
                """
            )
            c.execute("CREATE INDEX IF NOT EXISTS idx_principal ON receipts(principal_did, issued_at)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_issuer ON receipts(issuer_did, issued_at)")

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def append(self, receipt: dict[str, Any]) -> str:
        """Persist a signed receipt; returns the chain link it produces.

        Idempotent on (issuer_did, receipt_id) — re-appending the same receipt
        replaces it rather than duplicating (the spec's replay floor).
        """
        action = receipt.get("action") or {}
        link = chain_link(receipt)
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO receipts (receipt_id, issuer_did, principal_did, "
                "issued_at, category, counterparty_did, previous_receipt_hash, chain_link, "
                "receipt_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    receipt["receipt_id"],
                    receipt["issuer_did"],
                    receipt["principal_did"],
                    receipt["issued_at"],
                    action.get("category"),
                    action.get("counterparty_did"),
                    receipt.get("previous_receipt_hash"),
                    link,
                    json.dumps(receipt, separators=(",", ":")),
                ),
            )
        return link

    def _q(self, where: str, args: tuple[Any, ...], limit: int) -> list[dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute(
                f"SELECT receipt_json FROM receipts {where} ORDER BY issued_at DESC LIMIT ?",  # noqa: S608
                (*args, limit),
            ).fetchall()
        return [json.loads(r["receipt_json"]) for r in rows]

    def list_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._q("", (), limit)

    def list_for_principal(self, principal_did: str, limit: int = 100) -> list[dict[str, Any]]:
        return self._q("WHERE principal_did = ?", (principal_did,), limit)

    def list_for_issuer(self, issuer_did: str, limit: int = 100) -> list[dict[str, Any]]:
        return self._q("WHERE issuer_did = ?", (issuer_did,), limit)

    def get(self, receipt_id: str, issuer_did: str | None = None) -> dict[str, Any] | None:
        where = "WHERE receipt_id = ?" + (" AND issuer_did = ?" if issuer_did else "")
        args = (receipt_id, issuer_did) if issuer_did else (receipt_id,)
        rows = self._q(where, args, 1)
        return rows[0] if rows else None

    def count(self) -> int:
        with self._conn() as c:
            return int(c.execute("SELECT COUNT(*) FROM receipts").fetchone()[0])


IssuerLog = ReceiptLog
AgencyLog = ReceiptLog
