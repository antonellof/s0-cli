"""Human-readable Markdown report.

Designed for committed reports / GitHub PR comments. Findings are grouped
by file (more useful for fixing — open one file, fix all its issues, move
on) with a severity-counter table at the top. Long rule IDs get the
``.foo.foo`` semgrep duplication trimmed via ``short_rule_id``.
"""

from __future__ import annotations

from collections import Counter

from s0_cli.report._common import (
    SEV_COLOR,
    SEV_ORDER,
    group_by_file,
    short_rule_id,
)
from s0_cli.scanners.base import Finding

_SEV_BADGE = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


def to_markdown(findings: list[Finding], target_label: str = "(target)") -> str:
    if not findings:
        return f"# s0-cli scan: {target_label}\n\nNo findings.\n"

    by_sev = Counter(f.severity for f in findings)
    lines = [
        f"# s0-cli scan: {target_label}",
        "",
        f"Total findings: **{len(findings)}**",
        "",
        "| Severity | Count |",
        "| -------- | ----- |",
    ]
    for sev in SEV_ORDER:
        if by_sev[sev]:
            lines.append(f"| {_SEV_BADGE.get(sev, '')} {sev} | {by_sev[sev]} |")
    lines.append("")

    per_file = group_by_file(findings)

    lines.append("## Findings by file")
    lines.append("")
    for path, items in per_file.items():
        sev_summary = Counter(f.severity for f in items)
        sev_str = " ".join(
            f"{_SEV_BADGE.get(s, '')}{sev_summary[s]}"
            for s in SEV_ORDER
            if sev_summary[s]
        )
        lines.append(f"### `{path}` — {sev_str}")
        lines.append("")
        lines.append("| Line | Severity | Rule | Source | Message |")
        lines.append("| ---: | -------- | ---- | ------ | ------- |")
        for f in items:
            line = str(f.line) if f.line else "-"
            rule = short_rule_id(f.rule_id)
            msg = _md_escape((f.message or "").strip())
            if f.cwe:
                msg = f"{msg} _(CWE: {', '.join(f.cwe)})_"
            sev_cell = f"{_SEV_BADGE.get(f.severity, '')} {f.severity}"
            lines.append(
                f"| {line} | {sev_cell} | `{rule}` | {f.source} | {msg} |"
            )
        lines.append("")

        annotated = [f for f in items if f.snippet or f.why_real or f.fix_hint]
        for f in annotated:
            lines.append(
                f"<details><summary>"
                f"`{path}:{f.line}` — {short_rule_id(f.rule_id)}"
                f"</summary>"
            )
            lines.append("")
            if f.snippet:
                lines.append("```")
                lines.append(f.snippet)
                lines.append("```")
                lines.append("")
            if f.why_real:
                lines.append(f"**Why:** {f.why_real}")
                lines.append("")
            if f.fix_hint:
                lines.append(f"**Fix:** {f.fix_hint}")
                lines.append("")
            lines.append("</details>")
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


# `SEV_COLOR` is re-exported here for callers that want to colourize
# markdown output via tooling that consumes the same severity palette.
__all__ = ["to_markdown", "SEV_COLOR"]


def _md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")
