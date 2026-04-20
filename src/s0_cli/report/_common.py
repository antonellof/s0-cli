"""Shared helpers for the report writers.

Centralized so semgrep's `.foo.foo` rule-name duplication and the severity
ordering are fixed in one place rather than re-implemented per format.
"""

from __future__ import annotations

from s0_cli.scanners.base import Finding

SEV_ORDER = ["critical", "high", "medium", "low", "info"]

# Rich-style colour per severity. Used by the terminal renderer; other
# formats can ignore it.
SEV_COLOR = {
    "critical": "red",
    "high": "bright_red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}


def short_rule_id(rule_id: str) -> str:
    """Trim noisy rule IDs for human-readable display.

    Specifically:
    - Strip a duplicated trailing segment (semgrep's
      ``foo.bar.baz.detected-X.detected-X`` pattern collapses to
      ``foo.bar.baz.detected-X``).
    - Then keep only the last dotted segment if the result is still over
      60 chars — that's the leaf rule name humans actually scan for.
    """
    rid = rule_id.strip()
    if not rid:
        return "(no rule id)"
    parts = rid.split(".")
    if len(parts) >= 2 and parts[-1] == parts[-2]:
        parts = parts[:-1]
        rid = ".".join(parts)
    if len(rid) > 60 and len(parts) > 1:
        return parts[-1]
    return rid


def severity_rank(sev: str) -> int:
    try:
        return SEV_ORDER.index(sev)
    except ValueError:
        return len(SEV_ORDER)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Severity desc → file asc → line asc. Stable, deterministic across runs."""
    return sorted(
        findings,
        key=lambda f: (severity_rank(f.severity), f.path, f.line),
    )


def group_by_file(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Group findings by file path, preserving severity-then-line order."""
    out: dict[str, list[Finding]] = {}
    for f in sort_findings(findings):
        out.setdefault(f.path, []).append(f)
    return out
