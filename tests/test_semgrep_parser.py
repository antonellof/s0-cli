"""Parser-only tests for semgrep output (no semgrep binary required)."""

from __future__ import annotations

import json
from pathlib import Path

from s0_cli.scanners.semgrep import parse_semgrep_json

FIXTURE = Path(__file__).parent / "fixtures" / "semgrep_output.json"


def test_parses_two_findings():
    data = json.loads(FIXTURE.read_text())
    findings = parse_semgrep_json(data)
    assert len(findings) == 2


def test_severity_mapping():
    data = json.loads(FIXTURE.read_text())
    findings = parse_semgrep_json(data)
    severities = {f.severity for f in findings}
    assert "high" in severities
    assert "medium" in severities


def test_fingerprint_stable():
    data = json.loads(FIXTURE.read_text())
    a = parse_semgrep_json(data)
    b = parse_semgrep_json(data)
    assert [f.fingerprint() for f in a] == [f.fingerprint() for f in b]


def test_cwe_extracted():
    data = json.loads(FIXTURE.read_text())
    findings = parse_semgrep_json(data)
    assert any(any("CWE-89" in c for c in f.cwe) for f in findings)


def test_empty_input():
    assert parse_semgrep_json({}) == []
    assert parse_semgrep_json({"results": []}) == []
