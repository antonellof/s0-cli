"""Typer CLI: `s0 scan | eval | runs | doctor | version`."""

from __future__ import annotations

import asyncio
import shutil
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from s0_cli import __version__
from s0_cli.config import SEVERITY_RANK, get_settings
from s0_cli.eval.runner import EvalRunner, load_harness_by_name
from s0_cli.eval.validate import validate_harness
from s0_cli.harness.llm import have_provider_key
from s0_cli.harness.progress import reset_sink, set_sink
from s0_cli.report import to_json, to_markdown, to_sarif
from s0_cli.runs.cli import runs_app
from s0_cli.runs.store import RunStore, write_run
from s0_cli.scanners import REGISTRY as SCANNER_REGISTRY
from s0_cli.targets.diff import build_diff_target
from s0_cli.targets.file import build_file_target
from s0_cli.targets.repo import build_repo_target
from s0_cli.ui.progress import RichProgressSink

app = typer.Typer(
    name="s0",
    help="Security-Zero: a Meta-Harness-shaped agent for code security scanning.",
    no_args_is_help=True,
    add_completion=False,
)
app.add_typer(runs_app, name="runs")
console = Console()


@app.command("version")
def cmd_version() -> None:
    console.print(f"s0-cli {__version__}")


@app.command("doctor")
def cmd_doctor() -> None:
    """Sanity check: scanners installed, env keys present, runs dir writable."""
    settings = get_settings()
    table = Table(title="s0 doctor")
    table.add_column("check")
    table.add_column("ok")
    table.add_column("detail")

    for name, cls in SCANNER_REGISTRY.items():
        sc = cls()
        ok = sc.is_available()
        path = shutil.which(name) or "-"
        table.add_row(f"scanner:{name}", "yes" if ok else "no", path)

    table.add_row("model", "?", settings.model)
    table.add_row(
        "provider_key",
        "yes" if have_provider_key(settings.model) else "no",
        "checked env",
    )
    table.add_row("rg (ripgrep)", "yes" if shutil.which("rg") else "no", shutil.which("rg") or "-")
    table.add_row("git", "yes" if shutil.which("git") else "no", shutil.which("git") or "-")
    runs_ok = True
    try:
        settings.runs_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        runs_ok = False
        table.add_row("runs_dir", "no", f"{settings.runs_dir}: {e}")
    if runs_ok:
        table.add_row("runs_dir", "yes", str(settings.runs_dir))

    console.print(table)


@app.command("scan")
def cmd_scan(
    path: Path = typer.Argument(..., exists=True, help="File or directory to scan."),
    mode: str = typer.Option("repo", "--mode", help="repo|diff|file"),
    diff: str | None = typer.Option(None, "--diff", help="Git ref for diff mode."),
    harness: str | None = typer.Option(None, "--harness", help="Harness name."),
    fmt: str = typer.Option("markdown", "--format", "-f", help="markdown|json|sarif"),
    out: Path | None = typer.Option(None, "--out", "-o", help="Output file."),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip LLM; raw scanner findings only."),
    fail_on: str | None = typer.Option(
        None, "--fail-on", help="Exit non-zero if a finding meets this severity."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress preview output."),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Stream every progress event (scanner start/finish, LLM turn, tool call).",
    ),
    no_progress: bool = typer.Option(
        False,
        "--no-progress",
        help="Disable the live status spinner. Implied by --quiet.",
    ),
) -> None:
    """Scan a target with the configured inner harness."""
    settings = get_settings()
    harness_name = harness or settings.default_harness

    if mode == "repo":
        target = build_repo_target(path if path.is_dir() else path.parent)
    elif mode == "diff":
        if diff is None:
            raise typer.BadParameter("--diff REF is required in diff mode.")
        target = build_diff_target(path, diff)
    elif mode == "file":
        target = build_file_target([path])
    else:
        raise typer.BadParameter(f"Unknown mode: {mode}")

    h = load_harness_by_name(harness_name)
    if no_llm and hasattr(h, "with_no_llm"):
        h.with_no_llm()

    if not quiet:
        console.print(
            f"[bold]scan[/] target={target.display()} mode={mode} harness={harness_name} "
            f"model={settings.model} no_llm={no_llm}"
        )

    show_progress = (
        not quiet
        and not no_progress
        and (sys.stderr.isatty() or verbose)
    )
    if show_progress:
        progress_console = Console(stderr=True)
        with RichProgressSink(progress_console, verbose=verbose) as sink:
            token = set_sink(sink)
            try:
                result = asyncio.run(h.scan(target))
            finally:
                reset_sink(token)
    else:
        result = asyncio.run(h.scan(target))

    invocation = " ".join(["s0", "scan", str(path), "--mode", mode] + (["--no-llm"] if no_llm else []))
    store = RunStore(settings.runs_dir)
    run_path, run_id = write_run(
        store=store,
        harness=h,
        target_label=target.display(),
        invocation=invocation,
        config={
            "harness_name": harness_name,
            "target_label": target.display(),
            "invocation": invocation,
            "model": settings.model,
            "no_llm": no_llm,
            "mode": mode,
        },
        result=result,
    )

    text = _render(result.findings, fmt, target.display())
    if out is not None:
        out.write_text(text, encoding="utf-8")
        if not quiet:
            console.print(f"[green]wrote[/] {out}")
    else:
        if fmt == "markdown" and not quiet:
            console.print(text)
        elif not quiet:
            sys.stdout.write(text + "\n")

    if not quiet:
        console.print(f"[dim]run:[/] {run_path}")
        console.print(f"[dim]ended:[/] {result.ended_via} · usage={result.usage}")

    if fail_on is None:
        fail_on = settings.fail_on
    threshold = SEVERITY_RANK.get(fail_on, 99)
    if any(SEVERITY_RANK.get(f.severity, 0) >= threshold for f in result.findings):
        raise typer.Exit(code=1)


@app.command("eval")
def cmd_eval(
    harness: str | None = typer.Option(None, "--harness"),
    bench: Path | None = typer.Option(
        None, "--bench", help="Bench root (overrides --split)."
    ),
    split: str = typer.Option(
        "train", "--split", help="Bench split: train (visible to optimizer) or test (held out)."
    ),
    only: str | None = typer.Option(None, "--only", help="Comma-separated task IDs."),
    no_llm: bool = typer.Option(False, "--no-llm"),
    validate_only: bool = typer.Option(False, "--validate-only", help="Static checks only."),
    quiet: bool = typer.Option(False, "--quiet"),
) -> None:
    """Run a harness over the labeled bench and write a scored run."""
    settings = get_settings()
    name = harness or settings.default_harness

    if validate_only:
        from s0_cli.harnesses import __path__ as harnesses_path  # type: ignore[attr-defined]

        path = Path(harnesses_path[0]) / f"{name}.py"
        rep = validate_harness(path)
        for w in rep.warnings:
            console.print(f"[yellow]warn:[/] {w}")
        for e in rep.errors:
            console.print(f"[red]error:[/] {e}")
        if rep.ok:
            console.print(f"[green]ok[/] harness={name} class={rep.harness_class}")
            raise typer.Exit(code=0)
        raise typer.Exit(code=2)

    h = load_harness_by_name(name)
    if no_llm and hasattr(h, "with_no_llm"):
        h.with_no_llm()

    only_list = [x.strip() for x in only.split(",")] if only else None
    from s0_cli.eval.runner import resolve_bench_root

    bench_root = bench if bench is not None else resolve_bench_root(split)
    runner = EvalRunner(bench_root=bench_root, store=RunStore(settings.runs_dir))

    if not quiet:
        console.print(
            f"[bold]eval[/] harness={name} split={split} bench={bench_root} "
            f"only={only_list} no_llm={no_llm}"
        )

    summary = asyncio.run(
        runner.run(
            h,
            only=only_list,
            invocation=f"s0 eval --harness {name}" + (" --no-llm" if no_llm else ""),
            config_extra={"model": settings.model, "no_llm": no_llm},
        )
    )

    table = Table(title=f"eval: {name}")
    for col in ("task", "tp", "fp", "fn", "f1", "tokens", "turns", "ended"):
        table.add_column(col)
    for o in summary.tasks:
        table.add_row(
            o.task_id,
            str(o.score["tp"]),
            str(o.score["fp"]),
            str(o.score["fn"]),
            f"{o.score['f1']:.3f}",
            str(o.usage.get("input_tokens", 0)),
            str(o.usage.get("turns", 0)),
            o.ended_via,
        )
    console.print(table)
    console.print(f"[bold]aggregate[/]: {summary.aggregate}")


@app.command("optimize")
def cmd_optimize(
    iterations: int = typer.Option(3, "--iterations", "-n", help="Outer-loop iterations."),
    bench: Path | None = typer.Option(
        None, "--bench", help="Train bench root (overrides default bench/tasks_train)."
    ),
    test_bench: Path | None = typer.Option(
        None, "--test-bench", help="Held-out test bench root (overrides default bench/tasks_test)."
    ),
    only: str | None = typer.Option(None, "--only", help="Comma-separated bench task IDs."),
    skill: Path = typer.Option(Path("SKILL.md"), "--skill", help="SKILL.md path."),
    max_proposer_turns: int = typer.Option(25, "--max-turns", help="Max tool-loop turns per proposal."),
    no_llm: bool = typer.Option(
        False, "--no-llm", help="Stub mode (proposer + harness both skip LLM; smoke-test only)."
    ),
    skip_test_eval: bool = typer.Option(
        False, "--skip-test-eval", help="Skip the final held-out test-set evaluation phase."
    ),
    fresh: bool = typer.Option(
        False, "--fresh", help="Delete the target runs dir before starting (irreversible)."
    ),
    run_name: str | None = typer.Option(
        None,
        "--run-name",
        help="Isolate this session under runs/<run-name>/. Combine with --fresh for a clean slate.",
    ),
) -> None:
    """Outer Meta-Harness loop: propose -> validate -> eval, repeated.

    Each iteration: a coding-agent proposer reads `runs/` + `SKILL.md`, writes
    a new harness file under `src/s0_cli/harnesses/`, and the runner evaluates
    it on the bench. Each iteration writes one new run to `runs/`.
    """
    from s0_cli.harnesses import __path__ as harnesses_path  # type: ignore[attr-defined]
    from s0_cli.optimizer.loop import cli_run_optimizer_sync
    from s0_cli.prompts import __path__ as prompts_path  # type: ignore[attr-defined]

    settings = get_settings()
    only_list = [x.strip() for x in only.split(",")] if only else None

    if not no_llm and not have_provider_key(settings.model):
        console.print(
            f"[red]No API key found for model {settings.model}.[/red] "
            "Set ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY, "
            "or run with --no-llm for a smoke-test."
        )
        raise typer.Exit(code=2)

    from s0_cli.eval.runner import BENCH_ROOT_DEFAULT, BENCH_TEST_DEFAULT

    train_bench = bench if bench is not None else BENCH_ROOT_DEFAULT
    held_out_bench = test_bench if test_bench is not None else BENCH_TEST_DEFAULT

    console.print(
        f"[bold]optimize[/] iterations={iterations} train_bench={train_bench} "
        f"test_bench={held_out_bench if not skip_test_eval else '(skipped)'} "
        f"model={settings.model} no_llm={no_llm}"
    )

    cli_run_optimizer_sync(
        runs_dir=settings.runs_dir,
        bench_dir=train_bench,
        test_bench_dir=held_out_bench if not skip_test_eval else None,
        skill_md_path=skill,
        harnesses_dir=Path(harnesses_path[0]),
        prompts_dir=Path(prompts_path[0]),
        iterations=iterations,
        max_proposer_turns=max_proposer_turns,
        no_llm=no_llm,
        only_tasks=only_list,
        console=console,
        fresh=fresh,
        run_name=run_name,
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()


def _render(findings, fmt: str, label: str) -> str:
    if fmt == "json":
        return to_json(findings)
    if fmt == "sarif":
        return to_sarif(findings)
    if fmt == "markdown":
        return to_markdown(findings, target_label=label)
    raise typer.BadParameter(f"Unknown format: {fmt}")
