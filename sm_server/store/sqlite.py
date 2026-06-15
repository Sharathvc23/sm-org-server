"""SQLite implementation of ServerStore — the zero-config self-hostable default.

Uses parameterized queries throughout, so hostile agent_ids (the R3 injection
vectors in the conformance suite) are stored as inert data, never interpolated.
"""

from __future__ import annotations

import json
import sqlite3
import threading

from sm_arp import chain_link

from sm_server.store.base import Member

_SCHEMA = """
CREATE TABLE IF NOT EXISTS members (
    agent_id   TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    origin     TEXT NOT NULL,
    public_key TEXT NOT NULL,
    did_key    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS nonces (
    scope TEXT NOT NULL,
    nonce TEXT NOT NULL,
    PRIMARY KEY (scope, nonce)
);
CREATE TABLE IF NOT EXISTS trust_events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    kind     TEXT NOT NULL,
    delta    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_trust_agent ON trust_events (agent_id);
CREATE TABLE IF NOT EXISTS receipts (
    receipt_id            TEXT NOT NULL,
    issuer_did            TEXT NOT NULL,
    principal_did         TEXT NOT NULL,
    issued_at             TEXT NOT NULL,
    category              TEXT,
    counterparty_did      TEXT,
    previous_receipt_hash TEXT,
    chain_link            TEXT NOT NULL,
    receipt_json          TEXT NOT NULL,
    PRIMARY KEY (issuer_did, receipt_id)
);
CREATE INDEX IF NOT EXISTS idx_receipts_principal ON receipts (principal_did, issued_at);
CREATE INDEX IF NOT EXISTS idx_receipts_chain ON receipts (issuer_did, chain_link);
"""


class SqliteStore:
    def __init__(self, path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def get_member(self, agent_id: str) -> Member | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT agent_id, name, origin, public_key, did_key FROM members WHERE agent_id = ?",
                (agent_id,),
            ).fetchone()
        return Member(*row) if row else None

    def put_member(self, member: Member) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO members (agent_id, name, origin, public_key, did_key) "
                "VALUES (?, ?, ?, ?, ?)",
                (member.agent_id, member.name, member.origin, member.public_key, member.did_key),
            )
            self._conn.commit()

    def rotate_key(self, agent_id: str, new_public_key: str, new_did_key: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE members SET public_key = ?, did_key = ? WHERE agent_id = ?",
                (new_public_key, new_did_key, agent_id),
            )
            self._conn.commit()

    def consume_nonce(self, scope: str, nonce: str) -> bool:
        with self._lock:
            try:
                self._conn.execute("INSERT INTO nonces (scope, nonce) VALUES (?, ?)", (scope, nonce))
                self._conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def member_count(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT COUNT(*) FROM members").fetchone()[0])

    def list_members(self, limit: int = 50) -> list[Member]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT agent_id, name, origin, public_key, did_key FROM members ORDER BY agent_id LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [Member(*r) for r in rows]

    def record_trust_event(self, agent_id: str, kind: str, delta: float) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO trust_events (agent_id, kind, delta) VALUES (?, ?, ?)",
                (agent_id, kind, float(delta)),
            )
            self._conn.commit()

    def trust_score(self, agent_id: str) -> float:
        with self._lock:
            row = self._conn.execute(
                "SELECT COALESCE(SUM(delta), 0.0) FROM trust_events WHERE agent_id = ?",
                (agent_id,),
            ).fetchone()
        return float(row[0])

    def trust_history(self, agent_id: str) -> list[dict[str, object]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT kind, delta FROM trust_events WHERE agent_id = ? ORDER BY id",
                (agent_id,),
            ).fetchall()
        return [{"kind": k, "delta": d} for k, d in rows]

    # ── ARP Issuer Log ─────────────────────────────────────────────

    def append_receipt(self, receipt: dict[str, object]) -> str:
        link: str = chain_link(receipt)
        action = receipt.get("action")
        action = action if isinstance(action, dict) else {}
        with self._lock:
            self._conn.execute(
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
            self._conn.commit()
        return link

    def _receipts_query(self, where: str, args: tuple[object, ...], limit: int) -> list[dict[str, object]]:
        with self._lock:
            rows = self._conn.execute(
                f"SELECT receipt_json FROM receipts {where} ORDER BY issued_at DESC LIMIT ?",  # noqa: S608
                (*args, int(limit)),
            ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def get_receipt(self, receipt_id: str) -> dict[str, object] | None:
        rows = self._receipts_query("WHERE receipt_id = ?", (receipt_id,), 1)
        return rows[0] if rows else None

    def get_receipt_by_chain_link(self, issuer_did: str, chain_link: str) -> dict[str, object] | None:
        rows = self._receipts_query("WHERE issuer_did = ? AND chain_link = ?", (issuer_did, chain_link), 1)
        return rows[0] if rows else None

    def list_receipts(self, limit: int = 100) -> list[dict[str, object]]:
        return self._receipts_query("", (), limit)

    def list_receipts_for_principal(self, principal_did: str, limit: int = 100) -> list[dict[str, object]]:
        return self._receipts_query("WHERE principal_did = ?", (principal_did,), limit)

    def receipt_count(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT COUNT(*) FROM receipts").fetchone()[0])
