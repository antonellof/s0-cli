"""Runtime configuration for s0-cli.

Loaded from environment variables and `.env`. Every harness reads from the same
`Settings` object so that the run-store snapshot reflects the actual config used.

The CLI also propagates non-`S0_*` keys from `.env` (e.g. `OPENAI_API_KEY`)
into `os.environ` so that downstream libs like `litellm` see them. pydantic
only loads keys with the `S0_` prefix; provider keys are unprefixed by
convention and need this side-channel.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

Severity = Literal["info", "low", "medium", "high", "critical"]

SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="S0_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    model: str = "anthropic/claude-sonnet-4-5"
    default_harness: str = "baseline_v0_agentic"

    max_turns: int = 30
    token_budget: int = 200_000
    output_cap_bytes: int = 30_000

    runs_dir: Path = Path("./runs")
    fail_on: Severity = "high"

    temperature: float = 0.0
    request_timeout_sec: int = 120


_PROVIDER_KEYS = (
    # Hosted providers
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GROQ_API_KEY",
    "MISTRAL_API_KEY",
    "DEEPSEEK_API_KEY",
    # OpenRouter — gateway to ~100 hosted models
    # https://openrouter.ai/docs#models
    "OPENROUTER_API_KEY",
    "OPENROUTER_API_BASE",  # default: https://openrouter.ai/api/v1
    # Azure OpenAI
    "AZURE_API_KEY",
    "AZURE_API_BASE",
    "AZURE_API_VERSION",
    # Ollama — local (default http://localhost:11434) or cloud-hosted
    # https://docs.litellm.ai/docs/providers/ollama
    "OLLAMA_API_BASE",
    "OLLAMA_API_KEY",
    # OpenAI-compatible self-hosted endpoints (vLLM, llama.cpp, LM Studio, …).
    # Use S0_MODEL=openai/<model> + OPENAI_API_BASE=<url>.
    "OPENAI_API_BASE",
)


def _candidate_env_files(explicit: Path | None = None) -> list[Path]:
    """Return env-file search paths, in priority order (first wins).

    Resolved priority:
      1. Explicit path passed via `--env-file` (CLI) or `S0_ENV_FILE`.
      2. `./.env` in the current working directory (matches dev workflow).
      3. `~/.config/s0/.env` (XDG-style, the recommended location for the
         standalone binary).
      4. `~/.s0/.env` (shorter alias).

    All existing files are returned; the loader walks them in order and
    only sets keys that are not already populated, so an explicit path
    or the CWD `.env` always wins over the home-dir defaults.
    """
    paths: list[Path] = []
    if explicit is not None:
        paths.append(explicit)
    env_var = os.environ.get("S0_ENV_FILE")
    if env_var:
        paths.append(Path(env_var).expanduser())
    paths.append(Path(".env"))
    home = Path.home()
    paths.append(home / ".config" / "s0" / ".env")
    paths.append(home / ".s0" / ".env")
    seen: set[Path] = set()
    out: list[Path] = []
    for p in paths:
        try:
            resolved = p.expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if resolved in seen or not resolved.is_file():
            continue
        seen.add(resolved)
        out.append(resolved)
    return out


def _parse_env_file(path: Path) -> dict[str, str]:
    """Parse a `KEY=value` file. Lines starting with `#` are comments."""
    out: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return out
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            out[key] = value
    return out


def _load_dotenv_provider_keys(env_file: Path | None = None) -> list[Path]:
    """Best-effort: forward `.env` keys into `os.environ`.

    Two classes of keys are forwarded:

    - **Provider API keys** (``OPENAI_API_KEY``, ``ANTHROPIC_API_KEY``,
      ``OLLAMA_API_BASE``, …): litellm reads these directly from the
      process env, so without this side-channel they would be invisible
      when the env file lives in ``~/.config/s0/.env`` (pydantic only
      auto-loads ``./.env`` from the CWD).
    - **``S0_*`` settings** (e.g. ``S0_MODEL``): pydantic-settings
      *would* load them from ``./.env``, but again only from the CWD.
      Forwarding them here means a user's home-dir config picks up the
      same way the project-local ``./.env`` does — exactly what
      ``s0 init`` writes to.

    We never overwrite an already-set environment variable, so an
    explicit ``S0_MODEL=… s0 scan`` invocation always beats the file.

    Returns the list of files that were actually read.
    """
    loaded: list[Path] = []
    for path in _candidate_env_files(env_file):
        parsed = _parse_env_file(path)
        if not parsed:
            continue
        loaded.append(path)
        for key, value in parsed.items():
            if not value:
                continue
            # Forward provider keys (litellm) AND S0_* settings (pydantic),
            # but nothing else — we don't want a user's .env to silently
            # leak unrelated keys into the process env.
            if key not in _PROVIDER_KEYS and not key.startswith("S0_"):
                continue
            if os.environ.get(key):
                continue
            os.environ[key] = value
    return loaded


def get_settings(env_file: Path | None = None) -> Settings:
    _load_dotenv_provider_keys(env_file)
    return Settings()
