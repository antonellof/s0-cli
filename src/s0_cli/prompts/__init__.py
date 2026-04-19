"""Prompt templates colocated with the harnesses that consume them.

Each harness file owns its prompt template; the Phase-1 proposer is allowed to
edit either or both. We use plain `str.format` (no Jinja) to keep the surface
small and the proposer-visible diff legible.
"""

from __future__ import annotations

from pathlib import Path

PROMPTS_DIR = Path(__file__).parent


def load(name: str) -> str:
    p = PROMPTS_DIR / name
    if not p.exists():
        raise FileNotFoundError(f"Prompt template not found: {p}")
    return p.read_text(encoding="utf-8")
