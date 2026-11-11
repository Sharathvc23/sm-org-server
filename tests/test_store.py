"""SqliteStore — the default backend behind the ServerStore seam."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest
from sm_arp import Identity, build_action, chain_link, issue_receipt

from sm_server.store.base import Member, ReceiptConflict
from sm_server.store.sqlite import NONCE_TTL_S, SqliteStore


def _member(agent_id: str = "a1", origin: str = "sovereign") -> Member:
    return Member(agent_id, "Agent One", origin, "cHVia2V5", "did:key:zABC")


def _receipt(issuer: Identity, summary: str = "did a thing", **kw: object) -> dict[str, object]:
    r: dict[str, object] = issue_receipt(
        issuer,
        principal_did=issuer.did,
        action=build_action(category="data_shared", human_summary=summary),
        **kw,  # type: ignore[arg-type]
    )
    return r


# ── members ──────────────────────────────────────────────────────────


def test_add_get_and_count() -> None:
    store = SqliteStore(":memory:")
    assert store.get_member("a1") is None
    assert store.member_count() == 0
    assert store.add_member(_member()) is True
    got = store.get_member("a1")
    assert got is not None and got.name == "Agent One"
    assert store.member_count() == 1


def test_add_member_never_overwrites_an_existing_row() -> None:
    """The key of record is set once; only rotation changes it."""
    store = SqliteStore(":memory:")
    assert store.add_member(_member()) is True
    assert store.add_member(Member("a1", "Renamed", "sovereign", "bmV3a2V5", "did:key:zNEW")) is False
    got = store.get_member("a1")
    assert got is not None and got.name == "Agent One" and got.public_key == "cHVia2V5"
    assert store.member_count() == 1


def test_delete_member() -> None:
    store = SqliteStore(":memory:")
    store.add_member(_member())
    assert store.delete_member("a1") is True
    assert store.get_member("a1") is None
    assert store.delete_member("a1") is False


def test_rotate_key_updates_only_key_fields() -> None:
    store = SqliteStore(":memory:")
    store.add_member(_member())
    store.rotate_key("a1", "bmV3a2V5", "did:key:zNEW")
    got = store.get_member("a1")
    assert got is not None
    assert got.public_key == "bmV3a2V5" and got.did_key == "did:key:zNEW"
    assert got.name == "Agent One"  # untouched


def test_list_members_orders_and_limits() -> None:
    store = SqliteStore(":memory:")
    for i in range(5):
        store.add_member(_member(agent_id=f"a{i}"))
    listed = store.list_members(limit=3)
    assert [m.agent_id for m in listed] == ["a0", "a1", "a2"]


# ── nonces ───────────────────────────────────────────────────────────


def test_consume_nonce_detects_replay() -> None:
    store = SqliteStore(":memory:")
    assert store.consume_nonce("rotate:a1", "n1") is True
    assert store.consume_nonce("rotate:a1", "n1") is False  # replay
    assert store.consume_nonce("rotate:a2", "n1") is True  # another agent's scope is fresh


def test_consume_nonce_prunes_rows_older_than_the_ttl() -> None:
    store = SqliteStore(":memory:")
    assert store.consume_nonce("s", "old") is True
    # Age the row past the TTL by hand, then any insert prunes it.
    store._conn.execute("UPDATE nonces SET created_at = ?", (int(time.time()) - NONCE_TTL_S - 1,))
    store._conn.commit()
    assert store.consume_nonce("s", "fresh") is True
    assert store._conn.execute("SELECT COUNT(*) FROM nonces").fetchone()[0] == 1
    # Pruned means replayable again — which is why the TTL (24 h) dwarfs the
    # ±300 s window a replayed request would also have to survive.
    assert store.consume_nonce("s", "old") is True


def test_consume_nonce_keeps_rows_within_the_ttl() -> None:
    store = SqliteStore(":memory:")
    store.consume_nonce("s", "recent")
    store._conn.execute("UPDATE nonces SET created_at = ?", (int(time.time()) - NONCE_TTL_S + 60,))
    store._conn.commit()
    store.consume_nonce("s", "other")
    assert store.consume_nonce("s", "recent") is False


# ── trust ────────────────────────────────────────────────────────────


def test_trust_ledger_is_sum_of_deltas() -> None:
    store = SqliteStore(":memory:")
    assert store.trust_score("a1") == 0.0
    store.record_trust_event("a1", "intent_response_useful", 1.0)
    store.record_trust_event("a1", "complaint_validated", -3.0)
    assert store.trust_score("a1") == -2.0
    history = store.trust_history("a1")
    assert [e["kind"] for e in history] == ["intent_response_useful", "complaint_validated"]


# ── receipts: append-only ────────────────────────────────────────────


def test_append_identical_receipt_is_idempotent() -> None:
    store = SqliteStore(":memory:")
    r = _receipt(Identity.generate())
    link = store.append_receipt(r)
    assert store.append_receipt(dict(r)) == link
    assert store.receipt_count() == 1


def test_append_rewrite_of_existing_receipt_id_is_refused() -> None:
    store = SqliteStore(":memory:")
    me = Identity.generate()
    original = _receipt(me, "v1")
    store.append_receipt(original)
    rewritten = _receipt(me, "REWRITTEN", receipt_id=original["receipt_id"], issued_at=original["issued_at"])
    with pytest.raises(ReceiptConflict) as exc:
        store.append_receipt(rewritten)
    assert exc.value.reason == "receipt_rewrite"
    stored = store.get_receipt(str(original["receipt_id"]))
    assert stored is not None and stored["action"]["human_summary"] == "v1"  # type: ignore[index]
    assert store.receipt_count() == 1


def test_append_second_child_of_same_link_is_a_fork() -> None:
    store = SqliteStore(":memory:")
    me = Identity.generate()
    genesis = _receipt(me, "genesis")
    store.append_receipt(genesis)
    store.append_receipt(_receipt(me, "child-1", previous_receipt_hash=chain_link(genesis)))
    with pytest.raises(ReceiptConflict) as exc:
        store.append_receipt(_receipt(me, "child-2", previous_receipt_hash=chain_link(genesis)))
    assert exc.value.reason == "chain_fork"
    assert store.receipt_count() == 2


def test_fork_is_refused_by_the_database_too() -> None:
    """Defence in depth: the unique index holds even if a caller bypasses append_receipt."""
    store = SqliteStore(":memory:")
    me = Identity.generate()
    genesis = _receipt(me, "genesis")
    store.append_receipt(genesis)
    store.append_receipt(_receipt(me, "child-1", previous_receipt_hash=chain_link(genesis)))
    with pytest.raises(sqlite3.IntegrityError):
        store._conn.execute(
            "INSERT INTO receipts (receipt_id, issuer_did, principal_did, issued_at, previous_receipt_hash, "
            "chain_link, receipt_json) VALUES ('x', ?, ?, 'now', ?, 'sha256:0', '{}')",
            (me.did, me.did, chain_link(genesis)),
        )


def test_last_receipt_for_issuer_is_newest_by_issued_at_then_insertion() -> None:
    store = SqliteStore(":memory:")
    me, other = Identity.generate(), Identity.generate()
    first = _receipt(me, "first", issued_at="2026-01-01T00:00:00Z")
    second = _receipt(me, "second", issued_at="2026-01-02T00:00:00Z")
    same_time = _receipt(me, "same-time-later-insert", issued_at="2026-01-02T00:00:00Z")
    store.append_receipt(first)
    store.append_receipt(second)
    store.append_receipt(same_time)
    store.append_receipt(_receipt(other, "someone else", issued_at="2026-12-31T00:00:00Z"))
    last = store.last_receipt_for_issuer(me.did)
    assert last is not None and last["receipt_id"] == same_time["receipt_id"]
    assert store.last_receipt_for_issuer("did:key:znobody") is None


# ── file mode ────────────────────────────────────────────────────────


def test_file_store_is_durable_in_wal_mode(tmp_path: Path) -> None:
    db = tmp_path / "server.sqlite"
    store = SqliteStore(str(db))
    assert store._conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    store.add_member(_member())
    store.close()
    reopened = SqliteStore(str(db))
    assert reopened.member_count() == 1
    reopened.close()


def test_default_path_comes_from_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = tmp_path / "from-env.sqlite"
    monkeypatch.setenv("SERVER_DB_PATH", str(db))
    store = SqliteStore()
    assert store.path == str(db)
    store.close()
    assert db.exists()


def test_legacy_nonce_table_is_migrated(tmp_path: Path) -> None:
    db = tmp_path / "legacy.sqlite"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE nonces (scope TEXT NOT NULL, nonce TEXT NOT NULL, PRIMARY KEY (scope, nonce))")
    conn.execute("INSERT INTO nonces VALUES ('rotate:a', 'n')")
    conn.commit()
    conn.close()
    store = SqliteStore(str(db))
    assert store.consume_nonce("rotate:a", "n") is False  # legacy row still counts as seen
    assert store.consume_nonce("rotate:a", "n2") is True
    store.close()


def test_forked_legacy_log_refuses_to_open(tmp_path: Path) -> None:
    db = tmp_path / "forked.sqlite"
    store = SqliteStore(str(db))
    me = Identity.generate()
    genesis = _receipt(me, "genesis")
    store.append_receipt(genesis)
    store.append_receipt(_receipt(me, "c1", previous_receipt_hash=chain_link(genesis)))
    # Simulate the pre-fix log: drop the guard index and write a second child.
    store._conn.execute("DROP INDEX idx_receipts_parent")
    fork = _receipt(me, "c2", previous_receipt_hash=chain_link(genesis))
    store._conn.execute(
        "INSERT INTO receipts (receipt_id, issuer_did, principal_did, issued_at, previous_receipt_hash, "
        "chain_link, receipt_json) VALUES (?, ?, ?, ?, ?, ?, '{}')",
        (fork["receipt_id"], me.did, me.did, fork["issued_at"], chain_link(genesis), chain_link(fork)),
    )
    store._conn.commit()
    store.close()
    with pytest.raises(RuntimeError, match="hash-chain fork"):
        SqliteStore(str(db))
