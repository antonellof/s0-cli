"""Unit tests for optimizer/context.py: Pareto frontier + ranking + render."""

from __future__ import annotations

import json
from pathlib import Path

from s0_cli.optimizer.context import (
    FRONTIER_FILENAME,
    _pareto,
    build_context,
    write_frontier,
)


def _mk_run(tmp: Path, name: str, f1: float | None, tokens: int | None) -> Path:
    d = tmp / name
    d.mkdir(parents=True)
    score = {"f1": f1, "input_tokens": tokens, "tp": 0, "fp": 0, "fn": 0}
    (d / "score.json").write_text(json.dumps(score), encoding="utf-8")
    (d / "config.json").write_text(json.dumps({"harness_name": name.split("__")[1]}), encoding="utf-8")
    (d / "summary.md").write_text(f"# {name}\nf1={f1}\ntokens={tokens}\n", encoding="utf-8")
    return d


def test_build_context_empty(tmp_path: Path) -> None:
    skill = tmp_path / "SKILL.md"
    skill.write_text("hi proposer", encoding="utf-8")
    ctx = build_context(tmp_path / "runs", skill)
    assert ctx.skill_md == "hi proposer"
    assert ctx.runs == []
    assert ctx.pareto_ids == []
    assert ctx.best_f1 is None
    assert "no prior runs" in ctx.render()


def test_pareto_frontier_basic() -> None:
    from s0_cli.optimizer.context import RunEntry

    runs = [
        RunEntry("a", Path("a"), "h1", f1=0.6, precision=None, recall=None, tokens=100, turns=1, ended_via=None),
        RunEntry("b", Path("b"), "h2", f1=0.7, precision=None, recall=None, tokens=200, turns=1, ended_via=None),
        RunEntry("c", Path("c"), "h3", f1=0.5, precision=None, recall=None, tokens=50,  turns=1, ended_via=None),
        RunEntry("d", Path("d"), "h4", f1=0.4, precision=None, recall=None, tokens=300, turns=1, ended_via=None),
    ]
    frontier = _pareto(runs)
    ids = {r.run_id for r in frontier}
    assert "a" in ids and "b" in ids and "c" in ids
    assert "d" not in ids


def test_build_context_loads_runs_and_ranks(tmp_path: Path) -> None:
    runs_dir = tmp_path / "runs"
    _mk_run(runs_dir, "2026-01-01__seed1__aa", f1=0.4, tokens=1000)
    _mk_run(runs_dir, "2026-01-02__seed2__bb", f1=0.6, tokens=500)
    _mk_run(runs_dir, "2026-01-03__seed1__cc", f1=0.6, tokens=800)
    skill = tmp_path / "SKILL.md"
    skill.write_text("# SKILL", encoding="utf-8")

    ctx = build_context(runs_dir, skill)
    assert ctx.best_f1 == 0.6
    assert len(ctx.runs) == 3
    assert ctx.pareto_ids
    assert any("__seed2__" in pid for pid in ctx.pareto_ids)
    rendered = ctx.render(top_k=3)
    assert "Best F1 to date: 0.6" in rendered
    assert "seed2" in rendered


def test_write_frontier_snapshots_pareto(tmp_path: Path) -> None:
    runs_dir = tmp_path / "runs"
    _mk_run(runs_dir, "2026-01-01__seed1__aa", f1=0.4, tokens=1000)
    _mk_run(runs_dir, "2026-01-02__seed2__bb", f1=0.6, tokens=500)  # Pareto
    _mk_run(runs_dir, "2026-01-03__seed3__cc", f1=0.5, tokens=200)  # Pareto

    out = write_frontier(runs_dir)
    assert out.name == FRONTIER_FILENAME
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["runs_total"] == 3
    assert payload["best_f1"] == 0.6
    ids = {r["run_id"] for r in payload["frontier"]}
    assert any("__seed2__" in i for i in ids)
    assert any("__seed3__" in i for i in ids)
    assert payload["frontier_size"] == len(payload["frontier"])


def test_load_runs_skips_underscored_dirs(tmp_path: Path) -> None:
    """Auxiliary dirs (e.g. _frontier.json sidecar) must not appear in runs."""
    runs_dir = tmp_path / "runs"
    _mk_run(runs_dir, "2026-01-01__real__aa", f1=0.5, tokens=100)
    write_frontier(runs_dir)
    (runs_dir / "_aux").mkdir()  # any underscore-prefixed dir is excluded

    skill = tmp_path / "SKILL.md"
    skill.write_text("", encoding="utf-8")
    ctx = build_context(runs_dir, skill)
    assert len(ctx.runs) == 1
    assert ctx.runs[0].run_id.endswith("__aa")
