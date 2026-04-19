"""Bench runner.

Loads a harness, walks `bench/tasks_train/<task>/` (or `tasks_test/`), runs the
harness's `scan()` on `<task>/target/`, scores against `ground_truth.json`,
aggregates, and (unless `--dry-run`) writes a run to the run-store.

The default split is `train`. The held-out `test` split is only meant to be
used at the end of an `s0 optimize` run to measure generalization.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from s0_cli.eval.scorer import score_findings
from s0_cli.harness.base import Harness, ScanResult
from s0_cli.runs.store import RunStore, TaskTrace, write_run
from s0_cli.targets.repo import build_repo_target

BENCH_ROOT_DEFAULT = Path("bench/tasks_train")
BENCH_TEST_DEFAULT = Path("bench/tasks_test")


def resolve_bench_root(split: str) -> Path:
    """Map a split name to its bench directory."""
    if split == "train":
        return BENCH_ROOT_DEFAULT
    if split == "test":
        return BENCH_TEST_DEFAULT
    raise ValueError(f"Unknown bench split {split!r}; expected 'train' or 'test'.")


@dataclass
class TaskOutcome:
    task_id: str
    findings_count: int
    score: dict[str, Any]
    usage: dict[str, Any]
    ended_via: str
    duration_ms: int = 0


@dataclass
class EvalSummary:
    harness_name: str
    tasks: list[TaskOutcome] = field(default_factory=list)
    aggregate: dict[str, Any] = field(default_factory=dict)


class EvalRunner:
    def __init__(
        self,
        bench_root: Path = BENCH_ROOT_DEFAULT,
        store: RunStore | None = None,
    ):
        self.bench_root = bench_root
        self.store = store

    def discover_tasks(self, only: list[str] | None = None) -> list[Path]:
        if not self.bench_root.exists():
            return []
        tasks = sorted(p for p in self.bench_root.iterdir() if (p / "ground_truth.json").exists())
        if only:
            tasks = [t for t in tasks if t.name in set(only)]
        return tasks

    async def run(
        self,
        harness: Harness,
        only: list[str] | None = None,
        invocation: str = "s0 eval",
        config_extra: dict[str, Any] | None = None,
    ) -> EvalSummary:
        tasks = self.discover_tasks(only)
        summary = EvalSummary(harness_name=harness.name or type(harness).__name__)

        all_findings = []
        traces_for_run: list[TaskTrace] = []
        agg = {
            "tp": 0, "fp": 0, "fn": 0,
            "input_tokens": 0, "output_tokens": 0, "cached_input_tokens": 0,
            "turns": 0,
        }

        for task_dir in tasks:
            task_id = task_dir.name
            target_dir = task_dir / "target"
            gt_path = task_dir / "ground_truth.json"
            ground_truth = json.loads(gt_path.read_text(encoding="utf-8"))

            target = build_repo_target(target_dir)
            try:
                result: ScanResult = await harness.scan(target)
            except Exception as e:  # broken candidate harnesses are common in s0 optimize
                err_type = type(e).__name__
                result = ScanResult(
                    findings=[],
                    trace=[{"type": "error", "error": f"{err_type}: {e}"}],
                    usage={"input_tokens": 0, "output_tokens": 0, "cached_input_tokens": 0, "turns": 0},
                    ended_via=f"error:{err_type}",
                )

            scored = score_findings(result.findings, ground_truth)

            agg["tp"] += scored["tp"]
            agg["fp"] += scored["fp"]
            agg["fn"] += scored["fn"]
            for k in ("input_tokens", "output_tokens", "cached_input_tokens", "turns"):
                agg[k] += int(result.usage.get(k, 0))

            summary.tasks.append(
                TaskOutcome(
                    task_id=task_id,
                    findings_count=len(result.findings),
                    score=scored,
                    usage=result.usage,
                    ended_via=result.ended_via,
                )
            )

            all_findings.extend(result.findings)
            traces_for_run.append(
                TaskTrace(
                    task_id=task_id,
                    findings=list(result.findings),
                    trace=list(result.trace),
                    tool_calls=[
                        ev for ev in result.trace
                        if ev.get("type") == "llm_call" and ev.get("tool_calls")
                    ],
                    usage=result.usage,
                    ended_via=result.ended_via,
                    ground_truth=ground_truth,
                    scored=scored,
                )
            )

        summary.aggregate = _aggregate(agg)

        if self.store is not None and tasks:
            combined_result = ScanResult(
                findings=all_findings,
                trace=[],
                usage={k: agg[k] for k in ("input_tokens", "output_tokens", "cached_input_tokens", "turns")},
                ended_via="aggregated",
            )
            write_run(
                store=self.store,
                harness=harness,
                target_label=f"bench:{len(tasks)} tasks",
                invocation=invocation,
                config={
                    "harness_name": harness.name,
                    "target_label": f"bench:{len(tasks)} tasks",
                    "invocation": invocation,
                    **(config_extra or {}),
                },
                result=combined_result,
                score=summary.aggregate,
                task_traces=traces_for_run,
            )

        return summary


def _aggregate(agg: dict[str, Any]) -> dict[str, Any]:
    tp, fp, fn = agg["tp"], agg["fp"], agg["fn"]
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "input_tokens": agg["input_tokens"],
        "output_tokens": agg["output_tokens"],
        "cached_input_tokens": agg["cached_input_tokens"],
        "turns": agg["turns"],
    }


def load_harness_from_path(path: Path) -> Harness:
    spec = importlib.util.spec_from_file_location(f"_s0_harness_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load harness from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for obj in module.__dict__.values():
        if isinstance(obj, type) and issubclass(obj, Harness) and obj is not Harness:
            return obj()
    raise RuntimeError(f"No Harness subclass in {path}")


def load_harness_by_name(name: str) -> Harness:
    """Load a harness from `s0_cli.harnesses.<name>`."""
    module = importlib.import_module(f"s0_cli.harnesses.{name}")
    for obj in module.__dict__.values():
        if isinstance(obj, type) and issubclass(obj, Harness) and obj is not Harness:
            return obj()
    raise RuntimeError(f"No Harness subclass in s0_cli.harnesses.{name}")
