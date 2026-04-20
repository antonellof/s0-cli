"""``s0 init`` — interactive wizard that writes a minimal ``.env`` config.

Goal: make the standalone-binary install path one keystroke away from a
working scan. The wizard asks at most four questions (provider, model, API
key, where to save) and writes a clean, commented file with only the keys
that the user actually needs.

Re-runs are safe: the wizard refuses to overwrite an existing file unless
``--force`` is passed, and ``--non-interactive`` lets installers pipe
answers in (e.g. ``s0 init --non-interactive --provider openai
--api-key sk-... --model openai/gpt-4o-mini``).
"""

from __future__ import annotations

import contextlib
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

console = Console()


@dataclass(frozen=True)
class _Provider:
    key: str           # short id used by --provider
    label: str         # human label shown in the menu
    env_var: str       # name of the API-key env var (empty = no key needed)
    default_model: str # default S0_MODEL value
    needs_base: bool = False  # ask for API base URL (Ollama / OpenAI-compat)
    base_default: str = ""    # placeholder shown for the base URL prompt
    base_var: str = ""        # env var to write the base URL into
    notes: str = ""    # one-line hint shown in the menu


_PROVIDERS: list[_Provider] = [
    _Provider(
        key="openai",
        label="OpenAI",
        env_var="OPENAI_API_KEY",
        default_model="openai/gpt-4o-mini",
        notes="cheapest hosted option for daily scans",
    ),
    _Provider(
        key="anthropic",
        label="Anthropic (Claude)",
        env_var="ANTHROPIC_API_KEY",
        default_model="anthropic/claude-sonnet-4-5",
        notes="recommended default — strong reasoning",
    ),
    _Provider(
        key="gemini",
        label="Google Gemini",
        env_var="GEMINI_API_KEY",
        default_model="gemini/gemini-1.5-flash",
        notes="generous free tier",
    ),
    _Provider(
        key="openrouter",
        label="OpenRouter",
        env_var="OPENROUTER_API_KEY",
        default_model="openrouter/anthropic/claude-3.5-sonnet",
        notes="single key → ~100 hosted models",
    ),
    _Provider(
        key="groq",
        label="Groq",
        env_var="GROQ_API_KEY",
        default_model="groq/llama-3.3-70b-versatile",
        notes="very fast inference",
    ),
    _Provider(
        key="mistral",
        label="Mistral",
        env_var="MISTRAL_API_KEY",
        default_model="mistral/mistral-large-latest",
        notes="",
    ),
    _Provider(
        key="deepseek",
        label="DeepSeek",
        env_var="DEEPSEEK_API_KEY",
        default_model="deepseek/deepseek-chat",
        notes="",
    ),
    _Provider(
        key="ollama",
        label="Ollama (local or self-hosted)",
        env_var="",  # local default needs no key
        default_model="ollama/llama3.1",
        needs_base=True,
        base_default="http://localhost:11434",
        base_var="OLLAMA_API_BASE",
        notes="run models locally — no API key needed for default",
    ),
    _Provider(
        key="openai-compat",
        label="OpenAI-compatible endpoint (vLLM / llama.cpp / LM Studio)",
        env_var="OPENAI_API_KEY",
        default_model="openai/local-model",
        needs_base=True,
        base_default="http://localhost:8000/v1",
        base_var="OPENAI_API_BASE",
        notes="point at any OpenAI-API-shaped URL",
    ),
    _Provider(
        key="none",
        label="No LLM (raw scanners only)",
        env_var="",
        default_model="anthropic/claude-sonnet-4-5",
        notes="`s0 scan --no-llm` — no triage, no agent",
    ),
]


def _provider_by_key(key: str) -> _Provider:
    for p in _PROVIDERS:
        if p.key == key:
            return p
    raise typer.BadParameter(
        f"Unknown provider: {key}. "
        f"Choose one of: {', '.join(p.key for p in _PROVIDERS)}."
    )


def _default_target() -> Path:
    # Recommended location for the standalone binary: works regardless of
    # where the user runs `s0` from.
    return Path.home() / ".config" / "s0" / ".env"


def _project_target() -> Path:
    return Path.cwd() / ".env"


def _render_provider_menu() -> None:
    console.print("\n[bold]Pick your LLM provider:[/bold]\n")
    for i, p in enumerate(_PROVIDERS, start=1):
        suffix = f" [dim]— {p.notes}[/dim]" if p.notes else ""
        console.print(f"  [cyan]{i:2})[/cyan] {p.label}{suffix}")


def _prompt_provider() -> _Provider:
    _render_provider_menu()
    while True:
        raw = typer.prompt("\nProvider", default="2")  # default to Anthropic
        raw = raw.strip().lower()
        # Accept either "1"-"N" or the short key.
        if raw.isdigit():
            idx = int(raw)
            if 1 <= idx <= len(_PROVIDERS):
                return _PROVIDERS[idx - 1]
        else:
            for p in _PROVIDERS:
                if p.key == raw or p.label.lower().startswith(raw):
                    return p
        console.print(f"[red]Invalid choice:[/red] {raw}")


def _prompt_model(provider: _Provider) -> str:
    return typer.prompt(
        "Model (litellm name)",
        default=provider.default_model,
    ).strip()


def _prompt_api_key(provider: _Provider) -> str:
    if not provider.env_var:
        return ""
    while True:
        # hide_input=True echoes nothing; users can paste safely.
        key = typer.prompt(
            f"{provider.env_var}",
            hide_input=True,
            default="",
            show_default=False,
        ).strip()
        if not key:
            confirm = typer.confirm(
                "  No key entered. Write the file without it (you can edit later)?",
                default=False,
            )
            if confirm:
                return ""
            continue
        return key


def _prompt_base_url(provider: _Provider) -> str:
    if not provider.needs_base:
        return ""
    return typer.prompt(
        f"{provider.base_var}",
        default=provider.base_default,
    ).strip()


def _prompt_target() -> Path:
    default = _default_target()
    console.print(
        "\n[bold]Where should I save the config?[/bold]\n"
        f"  [cyan]1)[/cyan] {default}  [dim](recommended for the binary)[/dim]\n"
        f"  [cyan]2)[/cyan] {_project_target()}  [dim](project-local; commit-aware)[/dim]\n"
        "  [cyan]3)[/cyan] custom path"
    )
    raw = typer.prompt("Choice", default="1").strip()
    if raw in {"1", ""}:
        return default
    if raw == "2":
        return _project_target()
    if raw == "3":
        custom = typer.prompt("Path").strip()
        return Path(custom).expanduser()
    # Fallback: treat free text as a path.
    return Path(raw).expanduser()


def _build_env_text(
    *,
    provider: _Provider,
    model: str,
    api_key: str,
    base_url: str,
) -> str:
    """Compose a minimal, commented .env file.

    We only emit the keys the user actually needs, so the file stays
    readable. The full reference lives in `.env.example`.
    """
    lines: list[str] = [
        "# Generated by `s0 init`. Edit freely.",
        "# Reference: https://github.com/antonellof/s0-cli/blob/main/.env.example",
        "",
        f"S0_MODEL={model}",
        "",
    ]
    if provider.env_var:
        lines.append(f"# {provider.label} API key")
        lines.append(f"{provider.env_var}={api_key}")
        lines.append("")
    if provider.needs_base and base_url:
        lines.append(f"# {provider.label} endpoint")
        lines.append(f"{provider.base_var}={base_url}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _write_env_file(target: Path, text: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    # API keys → 0600 so other local users can't read them.
    # chmod is a best-effort no-op on Windows / restricted filesystems.
    with contextlib.suppress(OSError):
        target.chmod(stat.S_IRUSR | stat.S_IWUSR)


def _summary_panel(target: Path, provider: _Provider, model: str) -> Panel:
    body = (
        f"[bold green]Wrote[/bold green] {target}\n"
        f"  provider  [cyan]{provider.label}[/cyan]\n"
        f"  model     [cyan]{model}[/cyan]\n\n"
        "[bold]Try it:[/bold]\n"
        "  [cyan]s0 doctor[/cyan]              # verify keys + scanners\n"
        "  [cyan]s0 scan ./your-repo[/cyan]    # run a scan"
    )
    return Panel(body, title="s0 init", border_style="green")


def cmd_init(
    out: Path | None = typer.Option(
        None,
        "--out",
        "-o",
        help=(
            "Where to write the .env file. Default: prompts you to choose "
            "(typically ~/.config/s0/.env)."
        ),
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite the target file if it already exists.",
    ),
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive",
        "-y",
        help="Skip all prompts. Requires --provider (and --api-key for hosted providers).",
    ),
    provider: str | None = typer.Option(
        None,
        "--provider",
        help=(
            "Provider key for non-interactive mode. "
            "One of: " + ", ".join(p.key for p in _PROVIDERS) + "."
        ),
    ),
    api_key: str | None = typer.Option(
        None,
        "--api-key",
        help="API key for non-interactive mode (read from $S0_INIT_API_KEY if unset).",
    ),
    model: str | None = typer.Option(
        None,
        "--model",
        help="S0_MODEL override (defaults to the provider's recommended model).",
    ),
    base_url: str | None = typer.Option(
        None,
        "--base-url",
        help="API base URL (only relevant for ollama / openai-compat providers).",
    ),
) -> None:
    """Write a minimal ``.env`` config with your LLM provider and key."""
    # Resolve provider + model + key + base, depending on the mode.
    if non_interactive:
        if not provider:
            raise typer.BadParameter("--provider is required with --non-interactive.")
        prov = _provider_by_key(provider)
        chosen_model = (model or prov.default_model).strip()
        chosen_key = (api_key or os.environ.get("S0_INIT_API_KEY") or "").strip()
        if prov.env_var and not chosen_key:
            raise typer.BadParameter(
                f"--api-key (or $S0_INIT_API_KEY) is required for provider '{prov.key}'."
            )
        chosen_base = (base_url or prov.base_default if prov.needs_base else "").strip()
        target = (out or _default_target()).expanduser()
    else:
        console.print(
            Panel(
                "Quick setup: pick a provider, paste an API key, save.\n"
                "[dim]Press Ctrl-C any time to abort. Existing files won't be overwritten.[/dim]",
                title="s0 init",
                border_style="cyan",
            )
        )
        prov = _provider_by_key(provider) if provider else _prompt_provider()
        chosen_model = (model or _prompt_model(prov)).strip()
        if api_key is not None:
            chosen_key = api_key.strip()
        elif os.environ.get("S0_INIT_API_KEY"):
            chosen_key = os.environ["S0_INIT_API_KEY"].strip()
        else:
            chosen_key = _prompt_api_key(prov)
        chosen_base = (base_url if base_url is not None else _prompt_base_url(prov)).strip()
        target = (out or _prompt_target()).expanduser()

    # Refuse to clobber unless --force.
    if target.exists() and not force:
        console.print(
            f"[yellow]⚠[/yellow]  {target} already exists. "
            "Re-run with [cyan]--force[/cyan] to overwrite, or pick a different "
            "path with [cyan]--out PATH[/cyan]."
        )
        raise typer.Exit(code=1)

    text = _build_env_text(
        provider=prov,
        model=chosen_model,
        api_key=chosen_key,
        base_url=chosen_base,
    )
    try:
        _write_env_file(target, text)
    except OSError as e:
        console.print(f"[red]Failed to write[/red] {target}: {e}", style="red")
        raise typer.Exit(code=1) from e

    console.print(_summary_panel(target, prov, chosen_model))

    # Soft warning if the chosen target won't be auto-loaded by the
    # config search order — most users will never hit this, but if they
    # write to e.g. /etc/s0.env they should know.
    from s0_cli.config import _candidate_env_files  # local import: avoid CLI import cycle

    auto = {p.resolve() for p in _candidate_env_files()}
    try:
        resolved = target.resolve()
    except OSError:
        resolved = target
    if resolved not in auto:
        console.print(
            f"\n[yellow]Heads up:[/yellow] {target} is outside the default search path.\n"
            f"  Use it with [cyan]s0 --env-file {target} scan ...[/cyan]\n"
            f"  or export [cyan]S0_ENV_FILE={target}[/cyan]."
        )

    # Exit 0 so installers can chain on success.
    sys.exit(0)
