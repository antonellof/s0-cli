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
from s0_cli.harness.progress import emit as emit_progress
from s0_cli.harness.progress import reset_sink, set_sink
from s0_cli.init_cmd import cmd_init
from s0_cli.report import (
    to_csv,
    to_gitlab_codequality,
    to_json,
    to_junit_xml,
    to_markdown,
    to_sarif,
    to_terminal,
)
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


@app.callback()
def _global_options(
    env_file: Path | None = typer.Option(
        None,
        "--env-file",
        "-e",
        help=(
            "Path to a .env file with provider keys (e.g. OPENAI_API_KEY). "
            "Defaults to $S0_ENV_FILE, then ./.env, then ~/.config/s0/.env, "
            "then ~/.s0/.env. Useful for the standalone binary, where you "
            "may run `s0` from any directory."
        ),
    ),
) -> None:
    """Apply global options (env-file loading) before any subcommand runs."""
    # Side effect: copy provider keys from the resolved env file into
    # os.environ so that litellm + downstream code see them. We call this
    # here rather than relying on the per-command `get_settings()` so that
    # commands like `s0 doctor` (which reports provider-key presence) get
    # the loaded values too.
    if env_file is not None and not env_file.is_file():
        raise typer.BadParameter(
            f"--env-file path does not exist: {env_file}",
            param_hint="--env-file",
        )
    from s0_cli.config import _load_dotenv_provider_keys
    _load_dotenv_provider_keys(env_file)


@app.command("version")
def cmd_version() -> None:
    console.print(f"s0-cli {__version__}")


# Interactive `.env` wizard. Implementation lives in `init_cmd` to keep this
# file focused on top-level wiring.
app.command("init")(cmd_init)


SCANNER_DESCRIPTIONS: dict[str, str] = {
    "semgrep": "AST pattern matching across 30+ languages (default ruleset)",
    "bandit": "Python-specific AST checks (CWE-bound)",
    "ruff": "Python lint + 'S' security rules (PEP-8 + bandit overlap)",
    "gitleaks": "Secret detection in source + git history",
    "trivy": "Dependency CVEs, IaC misconfigs, container/secret scan",
    "hallucinated_import": "Detects imports of non-existent / typo-squatted packages",
    "supply_chain": "OSV-Scanner + OpenSSF Scorecard + guarddog (CVEs, repo trust, malicious pkgs)",
    "vibe_llm": "LLM-driven detector for intent-level vibe-code issues",
}


def _resolve_scanner_selection(
    *,
    harness_default: tuple[str, ...],
    include: list[str] | None,
    exclude: list[str] | None,
) -> tuple[str, ...]:
    """Apply --scanner / --exclude-scanner against the harness defaults."""
    if include and exclude:
        raise typer.BadParameter(
            "Use either --scanner or --exclude-scanner, not both."
        )

    valid = set(SCANNER_REGISTRY.keys())

    if include is not None:
        unknown = [s for s in include if s not in valid]
        if unknown:
            raise typer.BadParameter(
                f"Unknown scanner(s): {', '.join(unknown)}. "
                f"Available: {', '.join(sorted(valid))}"
            )
        # Preserve user-supplied order, drop duplicates.
        seen: set[str] = set()
        ordered: list[str] = []
        for s in include:
            if s not in seen:
                seen.add(s)
                ordered.append(s)
        return tuple(ordered)

    if exclude is not None:
        unknown = [s for s in exclude if s not in valid]
        if unknown:
            raise typer.BadParameter(
                f"Unknown scanner(s): {', '.join(unknown)}. "
                f"Available: {', '.join(sorted(valid))}"
            )
        excluded = set(exclude)
        return tuple(s for s in harness_default if s not in excluded)

    return harness_default


@app.command("scanners")
def cmd_scanners() -> None:
    """List every available scanner, whether it's installed, and a one-liner."""
    table = Table(title="s0 scanners")
    table.add_column("name", style="bold")
    table.add_column("installed")
    table.add_column("path / type")
    table.add_column("description")

    for name, cls in SCANNER_REGISTRY.items():
        sc = cls()
        ok = sc.is_available()
        # External CLI tools live on $PATH; built-in detectors don't.
        ext = shutil.which(name)
        if ext:
            location = ext
        elif ok:
            location = "(built-in)"
        else:
            location = "-"
        table.add_row(
            name,
            "[green]yes[/green]" if ok else "[red]no[/red]",
            location,
            SCANNER_DESCRIPTIONS.get(name, ""),
        )

    console.print(table)
    console.print(
        "\n[dim]Use[/dim] [cyan]s0 scan PATH --scanner semgrep --scanner bandit[/cyan] "
        "[dim]to restrict, or[/dim] [cyan]--exclude-scanner trivy[/cyan] [dim]to skip one.[/dim]"
    )


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
    fmt: str | None = typer.Option(
        None,
        "--format",
        "-f",
        help=(
            "Output format: terminal | markdown | json | sarif | csv | gitlab | junit. "
            "Defaults to `terminal` for interactive stdout, `markdown` otherwise."
        ),
    ),
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
    scanners: list[str] | None = typer.Option(
        None,
        "--scanner",
        "-s",
        help=(
            "Restrict to specific scanners (repeatable). "
            "Default: whatever the harness ships with. "
            "Use `s0 scanners` to list all available."
        ),
    ),
    exclude_scanners: list[str] | None = typer.Option(
        None,
        "--exclude-scanner",
        "-x",
        help="Skip these scanners (repeatable). Cannot be combined with --scanner.",
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

    selected = _resolve_scanner_selection(
        harness_default=tuple(getattr(h, "default_scanners", ()) or ()),
        include=scanners or None,
        exclude=exclude_scanners or None,
    )
    if selected != tuple(getattr(h, "default_scanners", ())):
        # Per-instance override; doesn't touch the class default.
        h.default_scanners = selected

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
    emit_progress("phase_start", name="persist", findings=len(result.findings))
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
    persist_size = (run_path / "findings.json").stat().st_size if (run_path / "findings.json").exists() else 0
    emit_progress("phase_done", name="persist", findings_bytes=persist_size)

    # Smart default: if --format wasn't passed, use the polished Rich
    # renderer when stdout is a TTY (interactive `s0 scan ./repo`) and
    # markdown for piped/file output (`s0 scan ./repo > report.md`).
    if fmt is None:
        fmt = "terminal" if (out is None and sys.stdout.isatty()) else "markdown"
    fmt = fmt.lower()

    emit_progress("phase_start", name="render", format=fmt, findings=len(result.findings))
    rendered = _render(
        result.findings,
        fmt,
        target.display(),
        workspace_root=target.root,
    )
    rendered_size = len(rendered) if isinstance(rendered, str) else 0
    emit_progress("phase_done", name="render", bytes=rendered_size)

    # Markdown printed to a TTY goes through Rich's Markdown grammar, which
    # wedges on multi-MB strings (verified: 16 MB → 30s+ no progress, see
    # commit 7695e69). When that's about to happen and we're not writing to
    # a file, print a one-line summary instead. Other text formats stream
    # through `sys.stdout.write` and don't have this problem; the terminal
    # format uses a Rich renderable that streams natively.
    LARGE_OUTPUT_BYTES = 1_000_000  # 1 MB

    if out is not None:
        # File destination: always serialize to a string. The terminal
        # renderer doesn't apply to files; coerce to markdown.
        if fmt == "terminal":
            text = to_markdown(result.findings, target_label=target.display())
        else:
            assert isinstance(rendered, str)
            text = rendered
        out.write_text(text, encoding="utf-8")
        if not quiet:
            console.print(f"[green]wrote[/] {out} ({len(text):,} bytes, {fmt})")
    elif quiet:
        pass
    elif fmt == "terminal":
        console.print(rendered)
    elif fmt == "markdown" and rendered_size > LARGE_OUTPUT_BYTES:
        console.print(
            f"[yellow]⚠[/yellow]  {len(result.findings):,} findings would render as "
            f"[bold]{rendered_size:,}[/bold] bytes of markdown — Rich would take minutes.\n"
            f"   Re-run with [cyan]--out report.md[/cyan], "
            f"[cyan]--format terminal[/cyan] for the rich UI, or "
            f"[cyan]--format json --out findings.json[/cyan] for tooling."
        )
    elif fmt == "markdown":
        # Markdown at < 1 MB — render through Rich for nice colours.
        console.print(rendered)
    else:
        # csv / json / sarif / gitlab / junit: plain text, stream out.
        assert isinstance(rendered, str)
        sys.stdout.write(rendered + "\n")

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
    candidates: int = typer.Option(
        1,
        "--candidates",
        "-k",
        help=(
            "Parallel proposals per iteration (default 1). With -k N, each iteration fans "
            "out N proposers with diverse temperature/seed/focus and keeps the highest-F1 winner. "
            "Cost scales linearly with N."
        ),
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
        candidates=candidates,
    )


def _render(findings, fmt: str, label: str, workspace_root: Path | None = None):
    """Dispatch to the right renderer.

    Returns ``str`` for serializable formats and a Rich ``RenderableType``
    for the ``terminal`` format. Callers MUST handle both.

    ``workspace_root`` (when provided) is used by the terminal renderer to
    resolve relative finding paths into ``file://`` URLs for clickable
    hyperlinks in modern terminals.
    """
    if fmt == "json":
        return to_json(findings)
    if fmt == "sarif":
        return to_sarif(findings)
    if fmt == "markdown":
        return to_markdown(findings, target_label=label)
    if fmt == "terminal":
        # Pass the live console width so the renderer can adapt its layout
        # (panel border on / off). Without this, the renderer instantiates
        # a fresh Console() which sometimes reports the default 80 cols
        # regardless of the actual terminal.
        return to_terminal(
            findings,
            target_label=label,
            width=console.size.width,
            workspace_root=workspace_root,
        )
    if fmt == "csv":
        return to_csv(findings)
    if fmt == "gitlab":
        return to_gitlab_codequality(findings)
    if fmt == "junit":
        return to_junit_xml(findings)
    raise typer.BadParameter(
        f"Unknown format: {fmt}. "
        "Choose one of: terminal, markdown, json, sarif, csv, gitlab, junit."
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
