"""Human-readable Markdown report."""

from __future__ import annotations

from collections import Counter

from s0_cli.scanners.base import Finding

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


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
    for sev in _SEV_ORDER:
        if by_sev[sev]:
            lines.append(f"| {sev} | {by_sev[sev]} |")
    lines.append("")

    grouped: dict[str, list[Finding]] = {sev: [] for sev in _SEV_ORDER}
    for f in findings:
        grouped.setdefault(f.severity, []).append(f)

    for sev in _SEV_ORDER:
        items = grouped.get(sev) or []
        if not items:
            continue
        lines.append(f"## {sev.title()} ({len(items)})")
        lines.append("")
        for f in items:
            lines.append(f"### `{f.rule_id}` — {f.path}:{f.line}")
            lines.append("")
            lines.append(f"_source:_ `{f.source}` · _confidence:_ {f.confidence:.2f}"
                         + (f" · _CWE:_ {', '.join(f.cwe)}" if f.cwe else ""))
            lines.append("")
            lines.append(f.message)
            if f.snippet:
                lines.append("")
                lines.append("```")
                lines.append(f.snippet)
                lines.append("```")
            if f.why_real:
                lines.append("")
                lines.append(f"**Why:** {f.why_real}")
            if f.fix_hint:
                lines.append("")
                lines.append(f"**Fix:** {f.fix_hint}")
            lines.append("")
    return "\n".join(lines)
