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
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GROQ_API_KEY",
    "MISTRAL_API_KEY",
    "DEEPSEEK_API_KEY",
    "OPENROUTER_API_KEY",
    "AZURE_API_KEY",
    "AZURE_API_BASE",
    "AZURE_API_VERSION",
)


def _load_dotenv_provider_keys(env_file: Path = Path(".env")) -> None:
    """Best-effort: copy provider API keys from `.env` into `os.environ`.

    pydantic-settings only loads `S0_*` keys (env_prefix). litellm reads
    provider keys directly from `os.environ`, so we need to forward them
    ourselves. We do NOT overwrite an already-set environment variable.
    Format is the standard `KEY=value` per line, with `#` comments allowed.
    """
    if not env_file.is_file():
        return
    try:
        text = env_file.read_text(encoding="utf-8")
    except OSError:
        return
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if not value or key not in _PROVIDER_KEYS:
            continue
        if os.environ.get(key):
            continue
        os.environ[key] = value


def get_settings() -> Settings:
    _load_dotenv_provider_keys()
    return Settings()
