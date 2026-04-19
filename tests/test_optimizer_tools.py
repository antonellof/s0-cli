"""Unit tests for optimizer/tools.py: write sandbox, name validation, dispatch."""

from __future__ import annotations

import json
from pathlib import Path

from s0_cli.optimizer.tools import ProposerToolContext, ProposerTools


def _mk_run(runs_dir: Path, name: str) -> Path:
    d = runs_dir / name
    d.mkdir(parents=True)
    (d / "score.json").write_text(json.dumps({"f1": 0.4, "input_tokens": 1000}), encoding="utf-8")
    (d / "config.json").write_text(json.dumps({"harness_name": "h"}), encoding="utf-8")
    (d / "summary.md").write_text("hello", encoding="utf-8")
    return d


def test_write_harness_sandbox_and_name(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    h = tmp_path / "harnesses"
    p = tmp_path / "prompts"
    h.mkdir()
    p.mkdir()
    runs.mkdir()

    ctx = ProposerToolContext(runs_dir=runs, harnesses_dir=h, prompts_dir=p, skill_md="", initial_summary="")
    tools = ProposerTools(ctx)

    bad = tools.dispatch("write_harness", {"name": "../etc/shadow", "source": "x"})
    assert isinstance(bad, dict) and "error" in bad

    seed_block = tools.dispatch("write_harness", {"name": "baseline_v0_agentic", "source": "x"})
    assert isinstance(seed_block, dict) and "error" in seed_block
    assert "Refusing" in seed_block["error"]

    ok = tools.dispatch("write_harness", {"name": "v1_demo", "source": "# hi\n"})
    assert isinstance(ok, dict) and ok.get("ok") is True
    assert (h / "v1_demo.py").is_file()
    assert ctx.written_harness == h / "v1_demo.py"


def test_finish_marks_completed(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    ctx = ProposerToolContext(
        runs_dir=runs, harnesses_dir=tmp_path, prompts_dir=tmp_path,
        skill_md="", initial_summary="",
    )
    tools = ProposerTools(ctx)
    out = tools.dispatch("finish", {"summary": "demo"})
    assert isinstance(out, dict) and out.get("ok") is True
    assert ctx.finished is True
    assert ctx.finish_summary == "demo"


def test_read_run_and_list_runs(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    _mk_run(runs, "2026-01-01__h__aa")

    ctx = ProposerToolContext(
        runs_dir=runs, harnesses_dir=tmp_path, prompts_dir=tmp_path,
        skill_md="", initial_summary="",
    )
    tools = ProposerTools(ctx)
    listed = tools.dispatch("list_runs", {})
    assert isinstance(listed, dict) and listed["count"] == 1

    rr = tools.dispatch("read_run", {"run_id": "2026-01-01__h__aa"})
    assert isinstance(rr, dict)
    assert rr["summary"] == "hello"
    assert rr["score"]["f1"] == 0.4


def test_unknown_tool_returns_error(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    ctx = ProposerToolContext(
        runs_dir=runs, harnesses_dir=tmp_path, prompts_dir=tmp_path,
        skill_md="", initial_summary="",
    )
    tools = ProposerTools(ctx)
    out = tools.dispatch("nope", {})
    assert isinstance(out, dict) and "error" in out
