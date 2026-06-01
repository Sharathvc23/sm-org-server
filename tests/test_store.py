"""SqliteStore — the default backend behind the ChapterStore seam."""

from __future__ import annotations

from chapter_core.store.base import Member
from chapter_core.store.sqlite import SqliteStore


def _member(agent_id: str = "a1", origin: str = "sovereign") -> Member:
    return Member(agent_id, "Agent One", origin, "cHVia2V5", "did:key:zABC")


def test_put_get_and_count() -> None:
    store = SqliteStore()
    assert store.get_member("a1") is None
    assert store.member_count() == 0
    store.put_member(_member())
    got = store.get_member("a1")
    assert got is not None and got.name == "Agent One"
    assert store.member_count() == 1


def test_put_is_upsert() -> None:
    store = SqliteStore()
    store.put_member(_member())
    store.put_member(Member("a1", "Renamed", "sovereign", "cHVi", "did:key:zABC"))
    got = store.get_member("a1")
    assert got is not None and got.name == "Renamed"
    assert store.member_count() == 1


def test_rotate_key_updates_only_key_fields() -> None:
    store = SqliteStore()
    store.put_member(_member())
    store.rotate_key("a1", "bmV3a2V5", "did:key:zNEW")
    got = store.get_member("a1")
    assert got is not None
    assert got.public_key == "bmV3a2V5" and got.did_key == "did:key:zNEW"
    assert got.name == "Agent One"  # untouched


def test_consume_nonce_detects_replay() -> None:
    store = SqliteStore()
    assert store.consume_nonce("rotate", "n1") is True
    assert store.consume_nonce("rotate", "n1") is False  # replay
    assert store.consume_nonce("other", "n1") is True  # different scope is fresh


def test_list_members_orders_and_limits() -> None:
    store = SqliteStore()
    for i in range(5):
        store.put_member(_member(agent_id=f"a{i}"))
    listed = store.list_members(limit=3)
    assert [m.agent_id for m in listed] == ["a0", "a1", "a2"]


def test_trust_ledger_is_sum_of_deltas() -> None:
    store = SqliteStore()
    assert store.trust_score("a1") == 0.0
    store.record_trust_event("a1", "intent_response_useful", 1.0)
    store.record_trust_event("a1", "complaint_validated", -3.0)
    assert store.trust_score("a1") == -2.0
    history = store.trust_history("a1")
    assert [e["kind"] for e in history] == ["intent_response_useful", "complaint_validated"]
