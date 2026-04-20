"""CSV report writer.

Suitable for spreadsheets, pandas, jq pipelines, or `column -s, -t` in a
shell. Schema kept small and stable — the JSON format covers the long tail
(raw scanner output, fingerprints) for callers that need it.
"""

from __future__ import annotations

import csv
import io

from s0_cli.report._common import sort_findings
from s0_cli.scanners.base import Finding

COLUMNS = (
    "severity",
    "source",
    "rule_id",
    "path",
    "line",
    "end_line",
    "cwe",
    "confidence",
    "message",
    "why_real",
    "fix_hint",
)


def to_csv(findings: list[Finding]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=COLUMNS, lineterminator="\n")
    writer.writeheader()
    for f in sort_findings(findings):
        writer.writerow(
            {
                "severity": f.severity,
                "source": f.source,
                "rule_id": f.rule_id,
                "path": f.path,
                "line": f.line,
                "end_line": f.end_line if f.end_line is not None else "",
                "cwe": ";".join(f.cwe),
                "confidence": f"{f.confidence:.2f}",
                "message": _flatten(f.message),
                "why_real": _flatten(f.why_real),
                "fix_hint": _flatten(f.fix_hint),
            }
        )
    return buf.getvalue()


def _flatten(s: str | None) -> str:
    """Collapse newlines + redundant spacing so each row stays single-line."""
    if not s:
        return ""
    return " ".join(s.split())
