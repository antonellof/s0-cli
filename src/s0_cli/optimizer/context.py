"""Context assembly for the proposer.

The proposer's input window is precious; this module ranks prior runs by
Pareto dominance + recency, attaches each one's harness source + score +
short trace excerpt, and prepends `SKILL.md`. The result is fed to the
proposer as a single user message it will then explore via tool calls.

Paper Section 3.2: "the proposer is shown the top-k Pareto-frontier
harnesses and a small sample of their traces, plus its standing skill."
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class RunEntry:
    """One prior run, summarized for proposer consumption."""

    run_id: str
    path: Path
    harness_name: str
    f1: float | None
    precision: float | None
    recall: float | None
    tokens: int | None
    turns: int | None
    ended_via: str | None
    score: dict[str, Any] = field(default_factory=dict)


@dataclass
class OptimizerContext:
    skill_md: str
    runs: list[RunEntry] = field(default_factory=list)
    pareto_ids: list[str] = field(default_factory=list)
    best_f1: float | None = None

    def render(self, top_k: int = 6) -> str:
        """Render context as a single Markdown blob for the proposer."""
        sections = ["# SKILL", self.skill_md, "", "# Prior runs"]
        if not self.runs:
            sections.append("(no prior runs; you are bootstrapping from the seed harnesses)")
        else:
            sections.append(f"Total runs: {len(self.runs)}")
            sections.append(f"Pareto frontier: {self.pareto_ids[:top_k]}")
            sections.append(f"Best F1 to date: {self.best_f1}")
            sections.append("")
            sections.append("Use `read_run`, `read_trace`, and `read_harness` to inspect the runs you care about.")
            sections.append("")
            sections.append("## Top-k summary (most recent and frontier first)")
            for r in self.runs[:top_k]:
                sections.append(
                    f"- `{r.run_id}` harness={r.harness_name} f1={r.f1} "
                    f"prec={r.precision} rec={r.recall} tokens={r.tokens} "
                    f"turns={r.turns} ended={r.ended_via}"
                )
        return "\n".join(sections)


def build_context(
    runs_dir: Path,
    skill_md_path: Path,
    *,
    limit: int = 30,
) -> OptimizerContext:
    """Read SKILL.md + the most recent runs, compute Pareto frontier."""
    skill = skill_md_path.read_text(encoding="utf-8") if skill_md_path.exists() else ""
    runs = _load_runs(runs_dir, limit=limit)
    pareto = _pareto(runs)
    pareto_ids = [r.run_id for r in pareto]
    best = max((r.f1 for r in runs if r.f1 is not None), default=None)
    runs_sorted = sorted(
        runs,
        key=lambda r: (
            0 if r.run_id in pareto_ids else 1,
            -(r.f1 or -1.0),
            r.run_id,
        ),
        reverse=False,
    )
    return OptimizerContext(
        skill_md=skill,
        runs=runs_sorted,
        pareto_ids=pareto_ids,
        best_f1=best,
    )


FRONTIER_FILENAME = "_frontier.json"


def write_frontier(runs_dir: Path) -> Path:
    """Recompute the Pareto frontier from runs/ and snapshot it to a JSON file.

    Stable artifact: makes the frontier inspectable from the shell, lets
    downstream tooling (CI badges, dashboards) consume it without walking
    the whole run-store, and gives a clean checkpoint between optimize
    iterations. Returns the path written.
    """
    import time

    runs = _load_runs(runs_dir, limit=10_000)
    pareto = _pareto(runs)
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "runs_total": len(runs),
        "frontier_size": len(pareto),
        "best_f1": max((r.f1 for r in runs if r.f1 is not None), default=None),
        "frontier": [
            {
                "run_id": r.run_id,
                "harness": r.harness_name,
                "f1": r.f1,
                "precision": r.precision,
                "recall": r.recall,
                "tokens": r.tokens,
                "turns": r.turns,
                "ended_via": r.ended_via,
            }
            for r in pareto
        ],
    }
    runs_dir.mkdir(parents=True, exist_ok=True)
    out = runs_dir / FRONTIER_FILENAME
    out.write_text(json.dumps(payload, indent=2, sort_keys=False), encoding="utf-8")
    return out


def _load_runs(runs_dir: Path, limit: int) -> list[RunEntry]:
    if not runs_dir.exists():
        return []
    out: list[RunEntry] = []
    # Run dirs look like "2026-04-19T13-37-21Z__baseline_v0_agentic__947a";
    # auxiliary dotfiles like _frontier.json are excluded by the .name filter.
    dirs = sorted(
        (p for p in runs_dir.iterdir() if p.is_dir() and not p.name.startswith("_")),
        key=lambda p: p.name,
        reverse=True,
    )[:limit]
    for d in dirs:
        score = _read_json(d / "score.json", default={}) or {}
        config = _read_json(d / "config.json", default={}) or {}
        out.append(
            RunEntry(
                run_id=d.name,
                path=d,
                harness_name=config.get("harness_name") or _name_from_id(d.name),
                f1=score.get("f1"),
                precision=score.get("precision"),
                recall=score.get("recall"),
                tokens=score.get("input_tokens") or score.get("total_tokens"),
                turns=score.get("turns"),
                ended_via=score.get("ended_via") or score.get("ended"),
                score=score,
            )
        )
    return out


def _pareto(runs: list[RunEntry]) -> list[RunEntry]:
    """Frontier in (F1 high, tokens low) space.

    Runs with no F1 or no tokens are excluded from the frontier (they're not
    comparable on both axes). They still appear in `runs` for the proposer to
    inspect.
    """
    candidates = [r for r in runs if r.f1 is not None and r.tokens is not None]
    frontier: list[RunEntry] = []
    for r in candidates:
        dominated = any(
            (other.f1 >= r.f1 and other.tokens <= r.tokens
             and (other.f1 > r.f1 or other.tokens < r.tokens))
            for other in candidates
            if other is not r
        )
        if not dominated:
            frontier.append(r)
    frontier.sort(key=lambda r: (-(r.f1 or 0.0), r.tokens or 0))
    return frontier


def _read_json(path: Path, default=None):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def _name_from_id(run_id: str) -> str:
    parts = run_id.split("__")
    return parts[1] if len(parts) >= 2 else "unknown"
