"""Tests for the candidate-strategy ladder + winner-picking logic."""

from __future__ import annotations

import pytest

from s0_cli.optimizer.loop import CandidateAttempt, _pick_winner
from s0_cli.optimizer.strategies import build_strategies


def test_build_strategies_is_deterministic_and_diverse() -> None:
    a = build_strategies(3)
    b = build_strategies(3)
    assert [s.slot for s in a] == [0, 1, 2]
    assert [s.slot for s in b] == [0, 1, 2]
    assert [s.label for s in a] == ["c0", "c1", "c2"]
    temps = [s.temperature for s in a]
    assert len(set(temps)) > 1, f"expected temperature diversity, got {temps}"
    seeds = [s.seed_hint for s in a]
    assert len(set(seeds)) > 1, f"expected seed-hint diversity, got {seeds}"
    focuses = [s.focus for s in a]
    assert len(set(focuses)) == 3, f"expected focus diversity, got {focuses}"


def test_build_strategies_n1_returns_greedy_default() -> None:
    [only] = build_strategies(1)
    assert only.slot == 0
    assert only.temperature == 0.0
    assert only.seed_hint == "baseline_v0_agentic"


def test_build_strategies_cycles_with_unique_slots_when_n_exceeds_ladder() -> None:
    s = build_strategies(7)
    assert [x.slot for x in s] == [0, 1, 2, 3, 4, 5, 6]
    assert [x.label for x in s] == [f"c{i}" for i in range(7)]


def test_build_strategies_rejects_zero_or_negative() -> None:
    with pytest.raises(ValueError):
        build_strategies(0)
    with pytest.raises(ValueError):
        build_strategies(-1)


def test_strategy_directive_mentions_focus_and_seed_and_label() -> None:
    s = build_strategies(2)[1]
    text = s.directive()
    assert s.focus in text
    assert s.seed_hint in text
    assert s.label in text


def _attempt(slot, success, f1=None, tokens=None) -> CandidateAttempt:
    return CandidateAttempt(
        slot=slot,
        label=f"c{slot}",
        temperature=0.0,
        seed_hint="x",
        focus="y",
        proposed_path=f"/tmp/h{slot}.py",
        success=success,
        eval_summary=(
            {
                "aggregate": {
                    "f1": f1,
                    "input_tokens": tokens or 0,
                    "output_tokens": 0,
                }
            }
            if success
            else None
        ),
    )


def test_pick_winner_prefers_highest_f1() -> None:
    attempts = [
        _attempt(0, True, f1=0.40, tokens=1000),
        _attempt(1, True, f1=0.62, tokens=5000),
        _attempt(2, True, f1=0.58, tokens=2000),
    ]
    winner = _pick_winner(attempts)
    assert winner is not None
    assert winner.slot == 1


def test_pick_winner_breaks_f1_tie_by_fewest_tokens() -> None:
    attempts = [
        _attempt(0, True, f1=0.60, tokens=8000),
        _attempt(1, True, f1=0.60, tokens=2000),
        _attempt(2, True, f1=0.60, tokens=5000),
    ]
    winner = _pick_winner(attempts)
    assert winner is not None
    assert winner.slot == 1


def test_pick_winner_ignores_failed_attempts() -> None:
    attempts = [
        _attempt(0, False),
        _attempt(1, True, f1=0.30, tokens=1000),
        _attempt(2, False),
    ]
    winner = _pick_winner(attempts)
    assert winner is not None
    assert winner.slot == 1


def test_pick_winner_returns_none_when_all_failed() -> None:
    attempts = [_attempt(0, False), _attempt(1, False)]
    assert _pick_winner(attempts) is None
