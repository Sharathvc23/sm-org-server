"""Trust ledger arithmetic — tier thresholds and deltas are frozen per major."""

from __future__ import annotations

import pytest

from chapter_core import trust


@pytest.mark.parametrize(
    ("score", "tier", "min_trust", "federate"),
    [
        (0, "new", 0, False),
        (19.5, "new", 0, False),
        (20, "established", 20, False),
        (49, "established", 20, False),
        (50, "trusted", 50, True),
        (74, "trusted", 50, True),
        (75, "core", 75, True),
        (1000, "core", 75, True),
    ],
)
def test_tier_for(score: float, tier: str, min_trust: int, federate: bool) -> None:
    row = trust.tier_for(score)
    assert row["tier"] == tier
    assert row["score_min"] == min_trust
    assert row["federate"] is federate


@pytest.mark.parametrize(
    ("score", "expected"),
    [(0, 20), (20, 50), (50, 75), (75, None), (200, None)],
)
def test_next_tier_min(score: float, expected: int | None) -> None:
    assert trust.next_tier_min(score) == expected


def test_thresholds_are_strictly_ascending() -> None:
    mins = [r["score_min"] for r in trust.TIER_THRESHOLDS]
    assert mins == sorted(mins)
    assert len(set(mins)) == len(mins)


def test_event_deltas_have_expected_signs() -> None:
    assert trust.EVENT_DELTAS["intent_response_useful"] > 0
    assert trust.EVENT_DELTAS["complaint_validated"] < 0
