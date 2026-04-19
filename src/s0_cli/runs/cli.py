"""`s0 runs` subcommands: query the run store.

Designed for the Phase-1 proposer agent to navigate prior experience cheaply,
matching paper §D ("a short CLI that lists the Pareto frontier, shows top-k
harnesses, and diffs code and results between pairs of runs").
"""

from __future__ import annotations

import difflib
import json
import shutil
import subprocess
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from s0_cli.config import get_settings
from s0_cli.runs.store import RunStore

runs_app = typer.Typer(help="Query the run store.", no_args_is_help=True)
console = Console()


def _store() -> RunStore:
    return RunStore(get_settings().runs_dir)


@runs_app.command("list")
def cmd_list(
    frontier: bool = typer.Option(False, "--frontier", help="Show only Pareto frontier."),
    limit: int = typer.Option(20, "--limit", "-n", help="Max rows."),
) -> None:
    store = _store()
    runs = store.list_runs()
    if not runs:
        console.print("[yellow]No runs in[/] " + str(store.root))
        return

    rows: list[dict] = []
    for p in runs:
        score_path = p / "score.json"
        score = json.loads(score_path.read_text()) if score_path.exists() else {}
        cfg_path = p / "config.json"
        cfg = json.loads(cfg_path.read_text()) if cfg_path.exists() else {}
        rows.append(
            {
                "id": p.name,
                "harness": cfg.get("harness_name") or p.name.split("__")[1] if "__" in p.name else "?",
                "target": cfg.get("target_label", "?"),
                "f1": score.get("f1"),
                "precision": score.get("precision"),
                "recall": score.get("recall"),
                "tokens": score.get("input_tokens") or score.get("total_tokens"),
                "ended": score.get("ended_via", "?"),
            }
        )

    if frontier:
        rows = _pareto(rows)

    rows = rows[:limit]
    table = Table(title=f"runs ({len(rows)})", show_lines=False)
    for col in ("id", "harness", "target", "f1", "precision", "recall", "tokens", "ended"):
        table.add_column(col)
    for r in rows:
        table.add_row(
            r["id"][:48],
            str(r["harness"]),
            str(r["target"])[:24],
            _fmt(r["f1"]),
            _fmt(r["precision"]),
            _fmt(r["recall"]),
            str(r["tokens"]) if r["tokens"] is not None else "-",
            str(r["ended"]),
        )
    console.print(table)


@runs_app.command("show")
def cmd_show(run_id: str) -> None:
    store = _store()
    path = store.find(run_id)
    if path is None:
        raise typer.BadParameter(f"Run not found: {run_id}")
    summary = (path / "summary.md").read_text() if (path / "summary.md").exists() else "(no summary)"
    console.print(summary)
    console.print(f"\n[dim]location:[/] {path}")


@runs_app.command("diff")
def cmd_diff(run_a: str, run_b: str) -> None:
    store = _store()
    a = store.find(run_a)
    b = store.find(run_b)
    if a is None or b is None:
        raise typer.BadParameter("One or both runs not found.")
    src_a = (a / "harness.py").read_text() if (a / "harness.py").exists() else ""
    src_b = (b / "harness.py").read_text() if (b / "harness.py").exists() else ""
    diff = difflib.unified_diff(
        src_a.splitlines(keepends=True),
        src_b.splitlines(keepends=True),
        fromfile=f"{a.name}/harness.py",
        tofile=f"{b.name}/harness.py",
    )
    console.print("".join(diff) or "(harness sources are identical)")
    score_a = _safe_load(a / "score.json")
    score_b = _safe_load(b / "score.json")
    console.print(f"\n[bold]score {a.name}:[/] {score_a}")
    console.print(f"[bold]score {b.name}:[/] {score_b}")


@runs_app.command("frontier")
def cmd_frontier() -> None:
    cmd_list(frontier=True, limit=200)


@runs_app.command("grep")
def cmd_grep(
    pattern: str,
    in_: str = typer.Option("traces", "--in", help="traces|harness|all"),
) -> None:
    store = _store()
    runs = store.list_runs()
    if not runs:
        console.print("[yellow]No runs to grep.[/]")
        return
    rg = shutil.which("rg")
    targets: list[Path] = []
    for p in runs:
        if in_ in {"traces", "all"} and (p / "traces").exists():
            targets.append(p / "traces")
        if in_ in {"harness", "all"} and (p / "harness.py").exists():
            targets.append(p / "harness.py")
    if not targets:
        console.print("[yellow]Nothing to grep.[/]")
        return
    if rg:
        cmd = [rg, "--line-number", "--no-heading", "-e", pattern, *map(str, targets)]
        subprocess.run(cmd, check=False)
    else:
        import re

        regex = re.compile(pattern)
        for t in targets:
            files = [t] if t.is_file() else list(t.rglob("*"))
            for f in files:
                if not f.is_file():
                    continue
                try:
                    for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                        if regex.search(line):
                            console.print(f"{f}:{i}:{line}")
                except OSError:
                    continue


@runs_app.command("tail-traces")
def cmd_tail_traces(run_id: str, task_id: str) -> None:
    store = _store()
    path = store.find(run_id)
    if path is None:
        raise typer.BadParameter(f"Run not found: {run_id}")
    tdir = path / "traces" / task_id
    if not tdir.exists():
        raise typer.BadParameter(f"Task not found in run: {task_id}")
    for fname in ("observation.txt", "tools.jsonl", "findings.json", "scored.json"):
        f = tdir / fname
        if f.exists():
            console.print(f"\n[bold]--- {fname} ---[/]")
            console.print(f.read_text())


def _pareto(rows: list[dict]) -> list[dict]:
    candidates = [r for r in rows if r.get("f1") is not None and r.get("tokens") is not None]
    frontier = []
    for r in candidates:
        dominated = any(
            (other["f1"] >= r["f1"] and other["tokens"] <= r["tokens"]
             and (other["f1"] > r["f1"] or other["tokens"] < r["tokens"]))
            for other in candidates
            if other is not r
        )
        if not dominated:
            frontier.append(r)
    return frontier


def _fmt(x) -> str:
    if x is None:
        return "-"
    if isinstance(x, float):
        return f"{x:.3f}"
    return str(x)


def _safe_load(p: Path):
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        return None
