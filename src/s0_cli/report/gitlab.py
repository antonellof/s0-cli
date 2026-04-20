"""GitLab Code Quality JSON report.

This is the same JSON contract used by Code Climate and consumed by
GitLab MR Code Quality widgets, GitHub Code Quality (via codeclimate
artifact action), and many third-party CI dashboards.

Schema reference:
  https://docs.gitlab.com/ee/ci/testing/code_quality.html#implement-a-custom-tool

Each finding maps to one issue with:
  - `description`     – human message
  - `check_name`      – rule id (mapped to short form)
  - `fingerprint`     – stable hash so MR widgets can dedupe across runs
  - `severity`        – one of: info | minor | major | critical | blocker
  - `location.path`   – file path
  - `location.lines.begin` – line number
"""

from __future__ import annotations

import json

from s0_cli.report._common import short_rule_id, sort_findings
from s0_cli.scanners.base import Finding

# s0-cli severity → GitLab Code Quality severity
SEVERITY_MAP = {
    "critical": "blocker",
    "high": "critical",
    "medium": "major",
    "low": "minor",
    "info": "info",
}


def to_gitlab_codequality(findings: list[Finding]) -> str:
    issues = []
    for f in sort_findings(findings):
        issues.append(
            {
                "type": "issue",
                "check_name": short_rule_id(f.rule_id),
                "description": f.message or short_rule_id(f.rule_id),
                "categories": _categories(f),
                "severity": SEVERITY_MAP.get(f.severity, "info"),
                "fingerprint": f.fingerprint(),
                "location": {
                    "path": f.path,
                    "lines": {"begin": max(f.line, 1)},
                },
            }
        )
    return json.dumps(issues, indent=2)


def _categories(f: Finding) -> list[str]:
    """Map source/CWE to GitLab Code Quality category buckets.

    GitLab accepts: Bug Risk, Clarity, Compatibility, Complexity, Duplication,
    Performance, Security, Style. Anything security-tool-flagged goes under
    Security; LLM-only "vibe" findings (intent-level issues) get Bug Risk
    additionally so reviewers don't tune them out as false positives.
    """
    cats = ["Security"]
    if f.source.startswith("vibe") or f.source.startswith("llm"):
        cats.append("Bug Risk")
    return cats
