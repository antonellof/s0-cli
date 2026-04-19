"""Harness layer: the inner-harness ABC and shared infrastructure.

The Meta-Harness paper (Lee et al., 2026) optimizes over single-file
Python harnesses. Everything in this module is the *fixed* surface that
those harnesses build on:

- `base.Harness`           -- ABC every harness subclasses
- `tools.Tools`            -- read-only tool surface (litellm-shaped)
- `loop.agent_loop`        -- KIRA-style multi-turn driver
- `bootstrap.env_snapshot` -- security-flavored env probe
- `llm.LLM`                -- thin litellm wrapper with retry + caching
- `anthropic_caching`      -- ephemeral cache_control helpers (ported from KIRA)

Harness *files* under `s0_cli.harnesses.*` may import from here and from
`s0_cli.scanners`, but nowhere else.
"""

from s0_cli.harness.base import Harness, HarnessRunResult, ScanResult
from s0_cli.harness.bootstrap import EnvSnapshot, env_snapshot
from s0_cli.harness.llm import LLM, LLMResponse
from s0_cli.harness.loop import agent_loop
from s0_cli.harness.tools import Tools

__all__ = [
    "Harness",
    "HarnessRunResult",
    "ScanResult",
    "EnvSnapshot",
    "env_snapshot",
    "LLM",
    "LLMResponse",
    "agent_loop",
    "Tools",
]
