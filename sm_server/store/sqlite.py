"""SQLite implementation of ServerStore — the zero-config self-hostable default.

Uses parameterized queries throughout, so hostile agent_ids (the R3 injection
vectors in the conformance suite) are stored as inert data, never interpolated.

The database is a file by default (``SERVER_DB_PATH``, ``./sm-server.sqlite``)
in WAL mode, so ``uvicorn sm_server.app:app`` keeps its members, ledger and
Issuer Log across restarts. ``":memory:"`` is for tests.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time

from sm_arp import canonical_bytes, chain_link

from sm_server.store.base import Member, ReceiptConflict

DEFAULT_DB_PATH = "./sm-server.sqlite"
NONCE_TTL_S = 24 * 60 * 60

_SCHEMA = """
CREATE TABLE IF NOT EXISTS members (
    agent_id   TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    origin     TEXT NOT NULL,
    public_key TEXT NOT NULL,
    did_key    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS nonces (
    scope      TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT 0,
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
CREATE INDEX IF NOT EXISTS idx_receipts_issuer_time ON receipts (issuer_did, issued_at);
"""

# One child per link (ARP §6.4): the database refuses a fork even if a caller
# bypasses append_receipt's own check. Created separately so a log that already
# holds a fork (written by a release before the append-only fix) fails loudly
# at startup instead of surfacing as an opaque constraint error later.
_FORK_INDEX = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_parent
    ON receipts (issuer_did, previous_receipt_hash)
    WHERE previous_receipt_hash IS NOT NULL
"""


def default_db_path() -> str:
    """``SERVER_DB_PATH`` (legacy ``CHAPTER_DB_PATH``), else ``./sm-server.sqlite``."""
    return os.environ.get("SERVER_DB_PATH") or os.environ.get("CHAPTER_DB_PATH") or DEFAULT_DB_PATH


class SqliteStore:
    def __init__(self, path: str | None = None) -> None:
        self._path = path or default_db_path()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            if self._path != ":memory:":
                # WAL: readers never block the writer and a crash mid-commit
                # leaves the file consistent. Only meaningful for a real file.
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(_SCHEMA)
            self._migrate()
            try:
                self._conn.execute(_FORK_INDEX)
            except sqlite3.IntegrityError as exc:
                raise RuntimeError(
                    f"receipt log at {self._path} already contains a hash-chain fork "
                    "(two receipts from one issuer share a previous_receipt_hash); "
                    "the log is not append-only and must be repaired before serving"
                ) from exc
            self._conn.commit()

    def _migrate(self) -> None:
        """Bring a database created by an earlier release up to this schema."""
        cols = {row[1] for row in self._conn.execute("PRAGMA table_info(nonces)")}
        if "created_at" not in cols:
            self._conn.execute("ALTER TABLE nonces ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0")
            # Rows from before the TTL existed get a full retention period from
            # now rather than being pruned on the next write.
            self._conn.execute("UPDATE nonces SET created_at = ?", (int(time.time()),))
        # After the column exists on every database, old or new.
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_nonces_created ON nonces (created_at)")

    @property
    def path(self) -> str:
        return self._path

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ── members ────────────────────────────────────────────────────

    def get_member(self, agent_id: str) -> Member | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT agent_id, name, origin, public_key, did_key FROM members WHERE agent_id = ?",
                (agent_id,),
            ).fetchone()
        return Member(*row) if row else None

    def add_member(self, member: Member) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO members (agent_id, name, origin, public_key, did_key) "
                "VALUES (?, ?, ?, ?, ?)",
                (member.agent_id, member.name, member.origin, member.public_key, member.did_key),
            )
            self._conn.commit()
            return cur.rowcount == 1

    def delete_member(self, agent_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM members WHERE agent_id = ?", (agent_id,))
            self._conn.commit()
            return cur.rowcount == 1

    def rotate_key(self, agent_id: str, new_public_key: str, new_did_key: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE members SET public_key = ?, did_key = ? WHERE agent_id = ?",
                (new_public_key, new_did_key, agent_id),
            )
            self._conn.commit()

    def consume_nonce(self, scope: str, nonce: str) -> bool:
        now = int(time.time())
        with self._lock:
            # Prune on write: rows older than the TTL can no longer be replayed
            # (the timestamp window is ±300 s; the feedback key is a UTC day).
            self._conn.execute("DELETE FROM nonces WHERE created_at < ?", (now - NONCE_TTL_S,))
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO nonces (scope, nonce, created_at) VALUES (?, ?, ?)",
                (scope, nonce, now),
            )
            self._conn.commit()
            return cur.rowcount == 1

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

    # ── trust ledger ───────────────────────────────────────────────

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
        issuer = receipt["issuer_did"]
        prev = receipt.get("previous_receipt_hash")
        with self._lock:
            existing = self._conn.execute(
                "SELECT receipt_json, chain_link FROM receipts WHERE issuer_did = ? AND receipt_id = ?",
                (issuer, receipt["receipt_id"]),
            ).fetchone()
            if existing is not None:
                stored = json.loads(existing[0])
                same = canonical_bytes(stored, include_signature=True) == canonical_bytes(
                    receipt, include_signature=True
                )
                if not same:
                    raise ReceiptConflict("receipt_rewrite")
                return str(existing[1])
            if prev is not None:
                child = self._conn.execute(
                    "SELECT 1 FROM receipts WHERE issuer_did = ? AND previous_receipt_hash = ?",
                    (issuer, prev),
                ).fetchone()
                if child is not None:
                    raise ReceiptConflict("chain_fork")
            self._conn.execute(
                "INSERT INTO receipts (receipt_id, issuer_did, principal_did, "
                "issued_at, category, counterparty_did, previous_receipt_hash, chain_link, "
                "receipt_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    receipt["receipt_id"],
                    issuer,
                    receipt["principal_did"],
                    receipt["issued_at"],
                    action.get("category"),
                    action.get("counterparty_did"),
                    prev,
                    link,
                    json.dumps(receipt, separators=(",", ":")),
                ),
            )
            self._conn.commit()
        return link

    def _receipts_query(self, where: str, args: tuple[object, ...], limit: int) -> list[dict[str, object]]:
        with self._lock:
            rows = self._conn.execute(
                f"SELECT receipt_json FROM receipts {where} ORDER BY issued_at DESC, rowid DESC LIMIT ?",  # noqa: S608
                (*args, int(limit)),
            ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def get_receipt(self, receipt_id: str) -> dict[str, object] | None:
        rows = self._receipts_query("WHERE receipt_id = ?", (receipt_id,), 1)
        return rows[0] if rows else None

    def get_receipt_by_chain_link(self, issuer_did: str, chain_link: str) -> dict[str, object] | None:
        rows = self._receipts_query("WHERE issuer_did = ? AND chain_link = ?", (issuer_did, chain_link), 1)
        return rows[0] if rows else None

    def last_receipt_for_issuer(self, issuer_did: str) -> dict[str, object] | None:
        rows = self._receipts_query("WHERE issuer_did = ?", (issuer_did,), 1)
        return rows[0] if rows else None

    def list_receipts(self, limit: int = 100) -> list[dict[str, object]]:
        return self._receipts_query("", (), limit)

    def list_receipts_for_principal(self, principal_did: str, limit: int = 100) -> list[dict[str, object]]:
        return self._receipts_query("WHERE principal_did = ?", (principal_did,), limit)

    def receipt_count(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT COUNT(*) FROM receipts").fetchone()[0])
