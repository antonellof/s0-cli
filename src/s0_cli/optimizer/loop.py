"""Outer loop: propose -> validate -> eval -> log -> repeat."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from s0_cli.config import get_settings
from s0_cli.eval.runner import EvalRunner, load_harness_from_path
from s0_cli.eval.validate import validate_harness
from s0_cli.optimizer.context import build_context
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
class OptimizerResult:
    iterations: list[IterationResult]
    best_f1_before: float | None
    best_f1_after: float | None
    runs_dir: Path
    elapsed_sec: float


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
) -> OptimizerResult:
    console = console or Console()
    started = time.monotonic()

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

    for i in range(1, iterations + 1):
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

    final_ctx = build_context(runs_dir, skill_md_path)
    elapsed = time.monotonic() - started

    _print_summary(console, iterations_log, best_before, final_ctx.best_f1, elapsed)

    return OptimizerResult(
        iterations=iterations_log,
        best_f1_before=best_before,
        best_f1_after=final_ctx.best_f1,
        runs_dir=runs_dir,
        elapsed_sec=elapsed,
    )


def _print_summary(
    console: Console,
    iterations: list[IterationResult],
    best_before: float | None,
    best_after: float | None,
    elapsed: float,
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
        f"best_f1: {best_before} -> [{color}]{best_after}[/{color}] "
        f"(delta={delta:+.3f}) elapsed={elapsed:.1f}s"
    )


def cli_run_optimizer_sync(**kwargs) -> OptimizerResult:
    """Sync wrapper for the typer command."""
    return asyncio.run(run_optimizer(**kwargs))
