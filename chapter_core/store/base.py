"""The storage seam — the one interface the HTTP layer depends on.

Everything a conformant chapter needs to persist goes through ``ChapterStore``.
The default backend is SQLite (zero-config, file-backed); Postgres or any other
store is a drop-in that satisfies this Protocol. Nothing above this interface
knows what the backend is — that is what makes the core self-hostable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Member:
    agent_id: str
    name: str
    origin: str  # deployment-declared provenance, e.g. "sovereign" (see CHAPTER_ORIGINS)
    public_key: str  # standard base64 of the 32-byte Ed25519 public key
    did_key: str


class ChapterStore(Protocol):
    """Persistence the conformant protocol surface requires."""

    def get_member(self, agent_id: str) -> Member | None: ...

    def put_member(self, member: Member) -> None: ...

    def rotate_key(self, agent_id: str, new_public_key: str, new_did_key: str) -> None: ...

    def consume_nonce(self, scope: str, nonce: str) -> bool:
        """Record (scope, nonce). Return True if fresh, False if already seen (replay)."""
        ...

    def member_count(self) -> int: ...

    def list_members(self, limit: int = 50) -> list[Member]: ...

    def record_trust_event(self, agent_id: str, kind: str, delta: float) -> None:
        """Append an immutable trust event. The agent's score is the SUM of deltas."""
        ...

    def trust_score(self, agent_id: str) -> float:
        """Authoritative score = SUM of recorded deltas (0.0 if none)."""
        ...

    def trust_history(self, agent_id: str) -> list[dict[str, object]]:
        """Ordered list of {kind, delta} events for the agent."""
        ...
