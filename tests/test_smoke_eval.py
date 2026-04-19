"""End-to-end smoke test: agentic harness with --no-llm against bench.

Does NOT call any LLM. Verifies the loop terminates, the scorer runs, and the
run-store writes a valid record. Use this to gate CI.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from s0_cli.eval.runner import EvalRunner, load_harness_by_name
from s0_cli.runs.store import RunStore

BENCH = Path(__file__).parent.parent / "bench" / "tasks_train"


@pytest.mark.asyncio
async def test_singleshot_runs_with_no_llm(tmp_path: Path):
    if not BENCH.exists():
        pytest.skip("bench/ not present")
    h = load_harness_by_name("baseline_v0_singleshot").with_no_llm()
    runner = EvalRunner(bench_root=BENCH, store=RunStore(tmp_path))
    summary = await runner.run(h, only=["sql_injection_min"])
    assert summary.harness_name == "baseline_v0_singleshot"
    assert len(summary.tasks) == 1


@pytest.mark.asyncio
async def test_agentic_runs_with_no_llm(tmp_path: Path):
    if not BENCH.exists():
        pytest.skip("bench/ not present")
    h = load_harness_by_name("baseline_v0_agentic").with_no_llm()
    runner = EvalRunner(bench_root=BENCH, store=RunStore(tmp_path))
    summary = await runner.run(h, only=["sql_injection_min"])
    assert len(summary.tasks) == 1
    o = summary.tasks[0]
    assert "f1" in o.score


@pytest.mark.asyncio
async def test_run_store_writes_artifacts(tmp_path: Path):
    if not BENCH.exists():
        pytest.skip("bench/ not present")
    h = load_harness_by_name("baseline_v0_singleshot").with_no_llm()
    store = RunStore(tmp_path)
    runner = EvalRunner(bench_root=BENCH, store=store)
    await runner.run(h, only=["sql_injection_min"])
    runs = store.list_runs()
    assert runs, "run-store must contain at least one run"
    run = runs[0]
    for required in ("harness.py", "config.json", "findings.json", "score.json", "summary.md"):
        assert (run / required).exists(), f"missing {required}"
    assert (run / "traces").is_dir()
