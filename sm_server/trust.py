"""Trust ledger arithmetic — server-set deltas, tier thresholds, score → tier.

These tables are part of the protocol, not a tuning knob: a server that
hand-rolls its own deltas or tiers diverges from every other server and the
conformance suite catches it. The values are frozen per protocol major; the
score of an agent is, by construction, the SUM of its event deltas — so an
authoritative ledger has zero drift between stored and recomputed scores.
"""

from __future__ import annotations

from typing import TypedDict


class TierRow(TypedDict):
    score_min: int
    tier: str
    open_calls_max: int
    ttl_days: int
    federate: bool


# Server-set, immutable per major (spec/0.X trust event deltas).
EVENT_DELTAS: dict[str, float] = {
    "intent_match_accepted": 0.5,
    "intent_response_useful": 1.0,
    "call_response_accepted": 0.5,
    "conversation_completed_positive": 1.0,
    "skill_attested_by_trusted": 2.0,
    "endorsement_received": 0.5,
    "tenure_milestone_30d": 1.0,
    "tenure_milestone_90d": 2.0,
    "tenure_milestone_180d": 5.0,
    "tenure_milestone_365d": 10.0,
    "revocation_received": -1.0,
    "complaint_validated": -3.0,
    "inactive_decay": -1.0,
}

# Ascending by score_min; `federate` gates cross-server participation.
TIER_THRESHOLDS: list[TierRow] = [
    {"score_min": 0, "tier": "new", "open_calls_max": 1, "ttl_days": 7, "federate": False},
    {"score_min": 20, "tier": "established", "open_calls_max": 3, "ttl_days": 30, "federate": False},
    {"score_min": 50, "tier": "trusted", "open_calls_max": 10, "ttl_days": 90, "federate": True},
    {"score_min": 75, "tier": "core", "open_calls_max": 30, "ttl_days": 180, "federate": True},
]


def tier_for(score: float) -> TierRow:
    """The highest tier whose score_min the score clears."""
    chosen = TIER_THRESHOLDS[0]
    for row in TIER_THRESHOLDS:
        if row["score_min"] <= score:
            chosen = row
    return chosen


def next_tier_min(score: float) -> int | None:
    """score_min of the next tier up, or None if already in the top tier."""
    for row in TIER_THRESHOLDS:
        if row["score_min"] > score:
            return row["score_min"]
    return None
