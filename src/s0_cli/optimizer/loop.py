"""Outer loop: propose -> validate -> eval -> log -> repeat."""

from __future__ import annotations

import asyncio
import contextlib
import shutil
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from s0_cli.config import get_settings
from s0_cli.eval.runner import EvalRunner, load_harness_from_path
from s0_cli.eval.validate import validate_harness
from s0_cli.optimizer.context import build_context, write_frontier
from s0_cli.optimizer.proposer import Proposer, ProposerOutput
from s0_cli.runs.store import RunStore


@dataclass
class IterationResult:
    iteration: int
    proposed_path: str | None
    success: bool  # proposer wrote a file AND validator passed AND eval ran
    skip_reason: str | None = None
    eval_summary: dict[str, Any] | None = None
    proposer_summary: str | None = None
    proposer_usage: dict[str, Any] = field(default_factory=dict)


@dataclass
class TestEvalResult:
    """Final held-out test-set evaluation of the best harness.

    Recorded so callers (and the summary table) can show whether the train-set
    F1 improvement actually generalized.
    """

    harness_name: str
    train_f1: float | None
    test_aggregate: dict[str, Any]
    skipped: bool = False
    skip_reason: str | None = None


@dataclass
class OptimizerResult:
    iterations: list[IterationResult]
    best_f1_before: float | None
    best_f1_after: float | None
    runs_dir: Path
    elapsed_sec: float
    test_eval: TestEvalResult | None = None


async def run_optimizer(
    *,
    runs_dir: Path,
    bench_dir: Path,
    skill_md_path: Path,
    harnesses_dir: Path,
    prompts_dir: Path,
    iterations: int = 3,
    max_proposer_turns: int = 25,
    no_llm: bool = False,
    only_tasks: list[str] | None = None,
    console: Console | None = None,
    test_bench_dir: Path | None = None,
    fresh: bool = False,
    run_name: str | None = None,
) -> OptimizerResult:
    console = console or Console()
    started = time.monotonic()

    if run_name is not None:
        if "/" in run_name or run_name.startswith("."):
            raise ValueError(
                f"run_name must be a single safe path segment, got {run_name!r}"
            )
        runs_dir = runs_dir / run_name
        console.print(f"[dim]using isolated runs dir:[/dim] {runs_dir}")

    if fresh:
        if runs_dir.exists():
            console.print(f"[yellow]--fresh: removing {runs_dir}[/yellow]")
            shutil.rmtree(runs_dir)
        runs_dir.mkdir(parents=True, exist_ok=True)

    if test_bench_dir is not None:
        try:
            train_resolved = bench_dir.resolve()
            test_resolved = test_bench_dir.resolve()
        except OSError:
            train_resolved = bench_dir
            test_resolved = test_bench_dir
        if train_resolved == test_resolved:
            raise ValueError(
                "Train bench and test bench resolve to the same directory "
                f"({train_resolved}). The held-out test set must be disjoint "
                "from the training set, otherwise final-test results overstate "
                "generalization."
            )

    initial_ctx = build_context(runs_dir, skill_md_path)
    best_before = initial_ctx.best_f1

    proposer = Proposer(
        runs_dir=runs_dir,
        harnesses_dir=harnesses_dir,
        prompts_dir=prompts_dir,
        max_turns=max_proposer_turns,
        no_llm=no_llm,
    )

    settings = get_settings()
    store = RunStore(runs_dir)
    eval_runner = EvalRunner(bench_root=bench_dir, store=store)

    iterations_log: list[IterationResult] = []

    # Graceful shutdown: first Ctrl+C asks for an early exit at the next
    # iteration boundary, persisting current results + frontier. A second
    # Ctrl+C falls through to KeyboardInterrupt and aborts.
    stop_flag = {"requested": False}
    prev_handler = signal.getsignal(signal.SIGINT)

    def _on_sigint(_signum, _frame):
        if stop_flag["requested"]:
            console.print("\n[red]second SIGINT — aborting now.[/red]")
            signal.signal(signal.SIGINT, prev_handler)
            raise KeyboardInterrupt
        stop_flag["requested"] = True
        console.print(
            "\n[yellow]SIGINT received: finishing current iteration, then exiting. "
            "Press Ctrl+C again to abort immediately.[/yellow]"
        )

    with contextlib.suppress(ValueError):  # main thread only
        signal.signal(signal.SIGINT, _on_sigint)

    for i in range(1, iterations + 1):
        if stop_flag["requested"]:
            console.print(f"[yellow]early exit before iteration {i}[/yellow]")
            break
        console.rule(f"[bold cyan]optimize iteration {i}/{iterations}")

        ctx = build_context(runs_dir, skill_md_path)
        console.print(
            f"context: {len(ctx.runs)} prior runs, "
            f"frontier={ctx.pareto_ids[:4]}, best_f1={ctx.best_f1}"
        )

        proposer_out: ProposerOutput = await proposer.propose(ctx)
        console.print(
            f"proposer: ended={proposer_out.ended_via} "
            f"wrote={proposer_out.harness_path} "
            f"summary={proposer_out.finish_summary[:160]!r}"
        )

        if not proposer_out.success or proposer_out.harness_path is None:
            iterations_log.append(
                IterationResult(
                    iteration=i,
                    proposed_path=str(proposer_out.harness_path) if proposer_out.harness_path else None,
                    success=False,
                    skip_reason="proposer did not call finish or wrote no harness",
                    proposer_summary=proposer_out.finish_summary,
                    proposer_usage=proposer_out.usage,
                )
            )
            continue

        report = validate_harness(proposer_out.harness_path)
        if not report.ok:
            console.print(f"[red]validator rejected:[/red] {report.errors}")
            iterations_log.append(
                IterationResult(
                    iteration=i,
                    proposed_path=str(proposer_out.harness_path),
                    success=False,
                    skip_reason=f"validator: {'; '.join(report.errors)}",
                    proposer_summary=proposer_out.finish_summary,
                    proposer_usage=proposer_out.usage,
                )
            )
            continue

        harness_name = proposer_out.harness_path.stem
        try:
            harness = load_harness_from_path(proposer_out.harness_path)
            if no_llm and hasattr(harness, "with_no_llm"):
                harness.with_no_llm()
        except Exception as e:
            console.print(f"[red]import failed:[/red] {e}")
            iterations_log.append(
                IterationResult(
                    iteration=i,
                    proposed_path=str(proposer_out.harness_path),
                    success=False,
                    skip_reason=f"import: {type(e).__name__}: {e}",
                    proposer_summary=proposer_out.finish_summary,
                    proposer_usage=proposer_out.usage,
                )
            )
            continue

        console.print(f"running eval on harness={harness_name}")
        summary = await eval_runner.run(
            harness,
            only=only_tasks,
            invocation=f"s0 optimize iter={i} harness={harness_name}",
            config_extra={
                "model": settings.model,
                "no_llm": no_llm,
                "from_optimizer": True,
                "iteration": i,
                "proposer_summary": proposer_out.finish_summary,
            },
        )

        agg = summary.aggregate
        console.print(
            f"[green]eval:[/green] f1={agg.get('f1')} "
            f"prec={agg.get('precision')} rec={agg.get('recall')} "
            f"tokens={agg.get('input_tokens', 0) + agg.get('output_tokens', 0)}"
        )

        iterations_log.append(
            IterationResult(
                iteration=i,
                proposed_path=str(proposer_out.harness_path),
                success=True,
                eval_summary={"aggregate": agg, "tasks": [
                    {"task_id": t.task_id, **t.score} for t in summary.tasks
                ]},
                proposer_summary=proposer_out.finish_summary,
                proposer_usage=proposer_out.usage,
            )
        )

        try:
            frontier_path = write_frontier(runs_dir)
            console.print(f"[dim]frontier snapshot ->[/dim] {frontier_path}")
        except Exception as e:  # noqa: BLE001 — non-fatal best-effort artifact
            console.print(f"[yellow]frontier snapshot failed:[/yellow] {e}")

    with contextlib.suppress(ValueError):
        signal.signal(signal.SIGINT, prev_handler)

    final_ctx = build_context(runs_dir, skill_md_path)

    test_eval: TestEvalResult | None = None
    if test_bench_dir is not None:
        test_eval = await _run_final_test_eval(
            console=console,
            iterations_log=iterations_log,
            harnesses_dir=harnesses_dir,
            test_bench_dir=test_bench_dir,
            store=store,
            settings_model=settings.model,
            no_llm=no_llm,
        )

    elapsed = time.monotonic() - started
    _print_summary(console, iterations_log, best_before, final_ctx.best_f1, elapsed, test_eval)

    return OptimizerResult(
        iterations=iterations_log,
        best_f1_before=best_before,
        best_f1_after=final_ctx.best_f1,
        runs_dir=runs_dir,
        elapsed_sec=elapsed,
        test_eval=test_eval,
    )


async def _run_final_test_eval(
    *,
    console: Console,
    iterations_log: list[IterationResult],
    harnesses_dir: Path,
    test_bench_dir: Path,
    store: RunStore,
    settings_model: str,
    no_llm: bool,
) -> TestEvalResult:
    """Pick the best train-set candidate from this session and re-score it on the held-out test set.

    "Best" = highest train-set F1 among iterations that actually evaluated.
    Ties are broken by lowest token usage (prefer the cheaper harness on the
    Pareto frontier). Returns a `TestEvalResult` even when skipped, so the
    summary table can show *why* the test phase did not run.
    """
    best: tuple[float, int, IterationResult] | None = None
    for it in iterations_log:
        if not it.success or not it.eval_summary:
            continue
        agg = it.eval_summary.get("aggregate") or {}
        f1 = float(agg.get("f1", 0.0) or 0.0)
        toks = int(agg.get("input_tokens", 0) or 0) + int(agg.get("output_tokens", 0) or 0)
        cand = (f1, -toks, it)  # max f1, then max -tokens (== min tokens)
        if best is None or cand > best:
            best = cand

    if best is None:
        console.print("[yellow]final test eval:[/yellow] no successful iteration to evaluate.")
        return TestEvalResult(
            harness_name="-",
            train_f1=None,
            test_aggregate={},
            skipped=True,
            skip_reason="no successful iteration",
        )

    train_f1, _neg_tokens, it = best
    if it.proposed_path is None:
        return TestEvalResult(
            harness_name="-",
            train_f1=train_f1,
            test_aggregate={},
            skipped=True,
            skip_reason="best iteration had no proposed_path",
        )

    harness_path = Path(it.proposed_path)
    if not harness_path.is_file():
        # Fallback: look it up under the harnesses directory by stem.
        candidate = harnesses_dir / f"{harness_path.stem}.py"
        if candidate.is_file():
            harness_path = candidate
        else:
            return TestEvalResult(
                harness_name=harness_path.stem,
                train_f1=train_f1,
                test_aggregate={},
                skipped=True,
                skip_reason=f"harness file disappeared: {harness_path}",
            )

    try:
        harness = load_harness_from_path(harness_path)
        if no_llm and hasattr(harness, "with_no_llm"):
            harness.with_no_llm()
    except Exception as e:
        return TestEvalResult(
            harness_name=harness_path.stem,
            train_f1=train_f1,
            test_aggregate={},
            skipped=True,
            skip_reason=f"import failed: {type(e).__name__}: {e}",
        )

    console.rule(f"[bold magenta]final test eval: {harness_path.stem}")
    console.print(
        f"running on held-out bench={test_bench_dir} "
        f"(train_f1={train_f1:.3f}, no_llm={no_llm})"
    )

    test_runner = EvalRunner(bench_root=test_bench_dir, store=store)
    test_summary = await test_runner.run(
        harness,
        invocation=f"s0 optimize final-test harness={harness_path.stem}",
        config_extra={
            "model": settings_model,
            "no_llm": no_llm,
            "from_optimizer": True,
            "phase": "final_test_eval",
        },
    )
    return TestEvalResult(
        harness_name=harness_path.stem,
        train_f1=train_f1,
        test_aggregate=test_summary.aggregate,
    )


def _print_summary(
    console: Console,
    iterations: list[IterationResult],
    best_before: float | None,
    best_after: float | None,
    elapsed: float,
    test_eval: TestEvalResult | None = None,
) -> None:
    table = Table(title="optimize summary", show_lines=False)
    table.add_column("iter")
    table.add_column("status")
    table.add_column("harness")
    table.add_column("f1")
    table.add_column("tokens")
    table.add_column("note")

    for it in iterations:
        if it.success and it.eval_summary:
            agg = it.eval_summary.get("aggregate", {})
            table.add_row(
                str(it.iteration),
                "[green]ok[/green]",
                Path(it.proposed_path or "?").stem,
                f"{agg.get('f1', 0.0):.3f}",
                str(agg.get("input_tokens", 0) + agg.get("output_tokens", 0)),
                (it.proposer_summary or "")[:60],
            )
        else:
            table.add_row(
                str(it.iteration),
                "[red]skip[/red]",
                Path(it.proposed_path).stem if it.proposed_path else "-",
                "-",
                "-",
                (it.skip_reason or "")[:60],
            )

    console.print(table)
    delta = (best_after or 0) - (best_before or 0)
    color = "green" if delta > 0 else "yellow" if delta == 0 else "red"
    console.print(
        f"best_f1 (train): {best_before} -> [{color}]{best_after}[/{color}] "
        f"(delta={delta:+.3f}) elapsed={elapsed:.1f}s"
    )

    if test_eval is not None:
        if test_eval.skipped:
            console.print(
                f"[yellow]final test eval skipped:[/yellow] {test_eval.skip_reason}"
            )
        else:
            agg = test_eval.test_aggregate
            train_f1 = test_eval.train_f1 or 0.0
            test_f1 = float(agg.get("f1", 0.0) or 0.0)
            gap = test_f1 - train_f1
            gap_color = "green" if gap >= -0.05 else "red"
            console.print(
                f"[bold]final test eval[/] harness={test_eval.harness_name} "
                f"train_f1={train_f1:.3f} -> "
                f"test_f1=[{gap_color}]{test_f1:.3f}[/{gap_color}] "
                f"(gap={gap:+.3f}, prec={agg.get('precision')}, rec={agg.get('recall')})"
            )


def cli_run_optimizer_sync(**kwargs) -> OptimizerResult:
    """Sync wrapper for the typer command."""
    return asyncio.run(run_optimizer(**kwargs))
