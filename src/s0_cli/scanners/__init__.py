"""Scanner integrations.

Each scanner is a small adapter that runs an external tool (or, in Phase 3, an
LLM-only detector) and yields normalized `Finding` objects.

Adding a new scanner is one file: implement the `Scanner` protocol and register
it in `REGISTRY` below.
"""

from __future__ import annotations

from s0_cli.scanners.bandit import BanditScanner
from s0_cli.scanners.base import Finding, Scanner, Severity
from s0_cli.scanners.gitleaks import GitleaksScanner
from s0_cli.scanners.ruff import RuffScanner
from s0_cli.scanners.semgrep import SemgrepScanner
from s0_cli.scanners.trivy import TrivyScanner

REGISTRY: dict[str, type[Scanner]] = {
    "semgrep": SemgrepScanner,
    "bandit": BanditScanner,
    "gitleaks": GitleaksScanner,
    "trivy": TrivyScanner,
    "ruff": RuffScanner,
}


def get_scanner(name: str) -> Scanner:
    cls = REGISTRY.get(name)
    if cls is None:
        raise KeyError(f"Unknown scanner: {name!r}. Available: {sorted(REGISTRY)}")
    return cls()


__all__ = ["Finding", "Scanner", "Severity", "REGISTRY", "get_scanner"]
