"""JUnit XML report.

Adopted by virtually every CI test reporter — GitHub Actions test summary,
GitLab `artifacts:reports:junit`, Jenkins JUnit plugin, CircleCI test
insights, Azure DevOps publish-test-results, etc. Treating each finding as
a "failed test" lets security results show up alongside unit tests in the
same dashboard.

We emit one ``<testsuite>`` per severity, with ``<testcase>`` per finding.
Higher-severity suites come first so dashboards that truncate on length
keep the worst issues visible.
"""

from __future__ import annotations

from xml.sax.saxutils import escape, quoteattr

from s0_cli.report._common import (
    SEV_ORDER,
    short_rule_id,
    sort_findings,
)
from s0_cli.scanners.base import Finding


def to_junit_xml(findings: list[Finding]) -> str:
    by_sev: dict[str, list[Finding]] = {sev: [] for sev in SEV_ORDER}
    for f in sort_findings(findings):
        by_sev.setdefault(f.severity, []).append(f)

    total = len(findings)
    suites = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuites name="s0-cli" tests="{total}" failures="{total}">',
    ]
    for sev in SEV_ORDER:
        items = by_sev.get(sev) or []
        if not items:
            continue
        suites.append(
            f'  <testsuite name="s0-cli/{sev}" tests="{len(items)}" '
            f'failures="{len(items)}">'
        )
        for f in items:
            suites.append(_testcase(f))
        suites.append("  </testsuite>")
    suites.append("</testsuites>")
    return "\n".join(suites) + "\n"


def _testcase(f: Finding) -> str:
    rule = short_rule_id(f.rule_id)
    classname = quoteattr(f.path or "?")
    name = quoteattr(f"{rule}:L{f.line}" if f.line else rule)
    typ = quoteattr(f.severity)
    msg = quoteattr((f.message or rule)[:240])
    body_parts = [
        f"rule: {f.rule_id}",
        f"source: {f.source}",
        f"path: {f.path}:{f.line}",
        f"severity: {f.severity}",
    ]
    if f.cwe:
        body_parts.append(f"cwe: {', '.join(f.cwe)}")
    if f.message:
        body_parts.append("")
        body_parts.append(f.message)
    if f.why_real:
        body_parts.append("")
        body_parts.append(f"why: {f.why_real}")
    if f.fix_hint:
        body_parts.append("")
        body_parts.append(f"fix: {f.fix_hint}")
    body = escape("\n".join(body_parts))
    return (
        f"    <testcase classname={classname} name={name}>\n"
        f"      <failure type={typ} message={msg}>{body}</failure>\n"
        "    </testcase>"
    )
