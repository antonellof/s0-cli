"""Runtime configuration for s0-cli.

Loaded from environment variables and `.env`. Every harness reads from the same
`Settings` object so that the run-store snapshot reflects the actual config used.
"""

from __future__ import annotations

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


def get_settings() -> Settings:
    return Settings()
