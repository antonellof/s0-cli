"""Unit tests for the scorer's TP/FP/FN matching."""

from __future__ import annotations

from s0_cli.eval.scorer import score_findings
from s0_cli.scanners.base import Finding


def _f(rule: str, path: str, line: int, sev: str = "high") -> Finding:
    return Finding(
        rule_id=rule, severity=sev, path=path, line=line,
        message="m", source="test", snippet=f"line {line}",
    )


def test_perfect_match():
    pred = [_f("r1", "a.py", 10)]
    gt = [{"rule_id": "any", "path": "a.py", "line": 10, "severity": "high"}]
    s = score_findings(pred, gt)
    assert s["tp"] == 1 and s["fp"] == 0 and s["fn"] == 0
    assert s["f1"] == 1.0


def test_within_tolerance():
    pred = [_f("r1", "a.py", 13)]
    gt = [{"rule_id": "x", "path": "a.py", "line": 10, "severity": "high"}]
    s = score_findings(pred, gt, line_tolerance=5)
    assert s["tp"] == 1


def test_outside_tolerance():
    pred = [_f("r1", "a.py", 100)]
    gt = [{"rule_id": "x", "path": "a.py", "line": 10, "severity": "high"}]
    s = score_findings(pred, gt, line_tolerance=5)
    assert s["tp"] == 0 and s["fp"] == 1 and s["fn"] == 1


def test_path_normalization():
    pred = [_f("r1", "./a.py", 10)]
    gt = [{"path": "a.py", "line": 10, "severity": "high"}]
    s = score_findings(pred, gt)
    assert s["tp"] == 1


def test_severity_off_by_mean():
    pred = [_f("r1", "a.py", 10, sev="medium")]
    gt = [{"path": "a.py", "line": 10, "severity": "critical"}]
    s = score_findings(pred, gt)
    assert s["tp"] == 1
    assert s["severity_off_by_mean"] == 2


def test_weighted_f1_prefers_critical():
    pred = [_f("r1", "a.py", 10, sev="critical")]
    gt = [{"path": "a.py", "line": 10, "severity": "critical"},
          {"path": "b.py", "line": 1, "severity": "low"}]
    s = score_findings(pred, gt)
    assert s["weighted_f1"] > s["f1"]
