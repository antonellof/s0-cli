"""Parser tests for the Phase-2 scanners.

These exercise `parse_*_json` directly with realistic vendor output so the
suite stays hermetic (no need for the actual binaries on CI). The integration
side is covered by the live `s0 doctor` + `s0 scan` runs documented in commits.
"""

from __future__ import annotations

from pathlib import Path

from s0_cli.scanners.bandit import parse_bandit_json
from s0_cli.scanners.gitleaks import parse_gitleaks_json
from s0_cli.scanners.ruff import parse_ruff_json
from s0_cli.scanners.trivy import parse_trivy_json


def test_parse_bandit_extracts_severity_confidence_cwe():
    raw = {
        "results": [
            {
                "test_id": "B608",
                "test_name": "hardcoded_sql_expressions",
                "filename": "/abs/proj/app.py",
                "line_number": 12,
                "line_range": [12, 13],
                "issue_severity": "MEDIUM",
                "issue_confidence": "HIGH",
                "issue_text": "Possible SQL injection vector through string-based query construction.",
                "code": "12 query = 'SELECT * FROM users WHERE id = ' + user_id\n",
                "issue_cwe": {"id": 89, "link": "https://cwe.mitre.org/data/definitions/89.html"},
            }
        ]
    }
    findings = parse_bandit_json(raw, root=Path("/abs/proj"))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "B608"
    assert f.severity == "medium"
    assert f.confidence == 1.0
    assert f.path == "app.py"  # absolute -> relative
    assert f.line == 12
    assert f.end_line == 13
    assert f.cwe == ("CWE-89",)
    assert f.source == "bandit"
    assert "SQL injection" in f.message


def test_parse_bandit_handles_empty_and_missing_fields():
    assert parse_bandit_json({"results": []}) == []
    assert parse_bandit_json({}) == []
    raw = {"results": [{"test_id": "B101", "filename": "a.py", "line_number": 1}]}
    findings = parse_bandit_json(raw)
    assert len(findings) == 1
    assert findings[0].severity == "medium"  # default
    assert findings[0].confidence == 0.7


def test_parse_ruff_marks_high_security_rules_high():
    raw = [
        {
            "code": "S608",
            "filename": "/abs/proj/app.py",
            "location": {"row": 5, "column": 1},
            "end_location": {"row": 5, "column": 50},
            "message": "Possible SQL injection via f-string.",
        },
        {
            "code": "S101",
            "filename": "/abs/proj/test_thing.py",
            "location": {"row": 9, "column": 5},
            "end_location": {"row": 9, "column": 30},
            "message": "Use of assert detected.",
        },
        {
            "code": "B008",
            "filename": "/abs/proj/util.py",
            "location": {"row": 3, "column": 1},
            "message": "Function call in default argument.",
        },
    ]
    findings = parse_ruff_json(raw, root=Path("/abs/proj"))
    sev_by_code = {f.rule_id: f.severity for f in findings}
    assert sev_by_code["S608"] == "high"
    assert sev_by_code["S101"] == "medium"
    assert sev_by_code["B008"] == "low"
    assert all(not f.path.startswith("/") for f in findings)


def test_parse_gitleaks_redacts_secret_in_message():
    raw = [
        {
            "RuleID": "aws-access-token",
            "Description": "AWS Access Key",
            "File": "/abs/proj/.env",
            "StartLine": 3,
            "EndLine": 3,
            "Match": "AKIAIOSFODNN7EXAMPLE",
            "Secret": "AKIAIOSFODNN7EXAMPLE",
        }
    ]
    findings = parse_gitleaks_json(raw, root=Path("/abs/proj"))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "high"
    assert f.cwe == ("CWE-798",)
    assert f.path == ".env"
    assert "AKIAIOSFODNN7EXAMPLE" not in f.message  # redacted
    assert "***" in f.message


def test_parse_gitleaks_short_secret_fully_redacted():
    raw = [{"RuleID": "x", "File": "a", "StartLine": 1, "Secret": "ab", "Match": "ab"}]
    [f] = parse_gitleaks_json(raw)
    assert "ab" not in f.message
    assert "***" in f.message


def test_parse_trivy_emits_vuln_secret_misconfig():
    raw = {
        "Results": [
            {
                "Target": "/abs/proj/requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-12345",
                        "PkgName": "requests",
                        "InstalledVersion": "2.20.0",
                        "FixedVersion": "2.31.0",
                        "Severity": "HIGH",
                        "Title": "RCE in requests",
                        "CweIDs": ["CWE-94"],
                    }
                ],
                "Secrets": [
                    {
                        "RuleID": "github-pat",
                        "StartLine": 7,
                        "EndLine": 7,
                        "Severity": "CRITICAL",
                        "Title": "GitHub Personal Access Token",
                        "Match": "ghp_xxx",
                    }
                ],
                "Misconfigurations": [
                    {
                        "ID": "DS002",
                        "Severity": "MEDIUM",
                        "Title": "Image user should not be root",
                        "CauseMetadata": {"StartLine": 1, "EndLine": 1},
                    }
                ],
            }
        ]
    }
    findings = parse_trivy_json(raw, root=Path("/abs/proj"))
    assert len(findings) == 3
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["CVE-2023-12345"].severity == "high"
    assert by_rule["CVE-2023-12345"].cwe == ("CWE-94",)
    assert "fix: 2.31.0" in by_rule["CVE-2023-12345"].message
    assert by_rule["github-pat"].severity == "critical"
    assert by_rule["github-pat"].cwe == ("CWE-798",)
    assert by_rule["DS002"].severity == "medium"
    assert all(not f.path.startswith("/") for f in findings)


def test_parse_trivy_handles_empty():
    assert parse_trivy_json({}) == []
    assert parse_trivy_json({"Results": []}) == []
    assert parse_trivy_json({"Results": [{"Target": "x"}]}) == []
