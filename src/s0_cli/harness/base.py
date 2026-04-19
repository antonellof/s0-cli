"""The `Harness` ABC.

Every file under `s0_cli.harnesses.*` must define exactly one subclass of
`Harness`. This is the unit the outer Meta-Harness loop will optimize.

Keep this surface stable. Adding a new optional class attribute is fine; renaming
or removing one is a breaking change for every prior harness in `runs/`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from s0_cli.scanners.base import Finding
from s0_cli.targets.base import Target


@dataclass
class ScanResult:
    """Output of a single `scan()` call.

    Fields:
        findings:   the deduped, triaged findings the harness wants to report.
        trace:      arbitrary structured log of what happened (model calls, tool
                    calls, timings, token usage). Written verbatim to runs/.
        usage:      aggregate token + cost accounting.
        ended_via:  "task_complete" | "budget_exhausted" | "error" | "no_findings".
    """

    findings: list[Finding] = field(default_factory=list)
    trace: list[dict[str, Any]] = field(default_factory=list)
    usage: dict[str, int | float] = field(default_factory=dict)
    ended_via: str = "task_complete"


@dataclass
class HarnessRunResult:
    """Outer wrapper used by the evaluator. Scan result + identity metadata."""

    harness_name: str
    target_label: str
    result: ScanResult


class Harness(ABC):
    """Subclass this to define a new inner harness.

    Class attributes (all overridable per harness):
        name:               unique identifier; must match the filename.
        description:        one-line summary, surfaced in `s0 runs show`.
        max_turns:          hard cap on tool-loop iterations. 1 = single shot.
        token_budget:       soft cap on input tokens summed across the loop.
        output_cap_bytes:   per-tool-observation byte cap (KIRA: 30000).
        default_scanners:   which scanners the harness will invoke through the
                            `run_scanner` tool (or directly in `scan()`).
    """

    name: str = ""
    description: str = ""
    max_turns: int = 30
    token_budget: int = 200_000
    output_cap_bytes: int = 30_000
    default_scanners: tuple[str, ...] = ("semgrep",)

    @abstractmethod
    async def scan(self, target: Target) -> ScanResult:
        """Run the harness against `target` and return findings + trace."""
        raise NotImplementedError
