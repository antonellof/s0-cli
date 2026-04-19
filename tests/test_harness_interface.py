"""Sanity checks on the Harness ABC and tool layer."""

from __future__ import annotations

from pathlib import Path

import pytest

from s0_cli.harness.base import Harness, ScanResult
from s0_cli.harness.tools import ToolContext, Tools
from s0_cli.scanners.base import Finding
from s0_cli.targets.repo import build_repo_target


class _NoopHarness(Harness):
    name = "noop_test"
    max_turns = 1

    async def scan(self, target):  # noqa: ARG002
        return ScanResult(findings=[])


def test_harness_subclass_must_be_constructible():
    h = _NoopHarness()
    assert h.name == "noop_test"


def test_scanresult_default_factories():
    r = ScanResult()
    assert r.findings == []
    assert r.trace == []
    assert r.usage == {}


def test_finding_fingerprint_dedups_across_rules(tmp_path: Path):
    a = Finding(rule_id="bandit.B608", severity="high", path="a.py", line=10,
                message="x", source="bandit", snippet="cur.execute(query)")
    b = Finding(rule_id="python.lang.security.sql-injection", severity="high",
                path="a.py", line=10, message="x", source="semgrep",
                snippet="cur.execute(query)")
    assert a.fingerprint() == b.fingerprint()


def test_tools_dispatch_unknown(tmp_path: Path):
    target = build_repo_target(tmp_path)
    ctx = ToolContext(target=target)
    tools = Tools(ctx)
    out = tools.dispatch("nonexistent", {})
    assert isinstance(out, dict) and "error" in out


def test_tools_add_finding_and_complete(tmp_path: Path):
    target = build_repo_target(tmp_path)
    ctx = ToolContext(target=target)
    tools = Tools(ctx)
    tools.dispatch("add_finding", {
        "rule_id": "x", "severity": "high", "path": "a.py", "line": 1,
        "message": "m", "source": "test",
    })
    tools.dispatch("task_complete", {})
    assert len(ctx.findings) == 1
    assert ctx.completed


def test_tools_path_escape_blocked(tmp_path: Path):
    target = build_repo_target(tmp_path)
    ctx = ToolContext(target=target)
    tools = Tools(ctx)
    out = tools.dispatch("read_file", {"path": "/etc/passwd"})
    assert isinstance(out, dict) and "error" in out


@pytest.mark.asyncio
async def test_noop_harness_scan(tmp_path: Path):
    target = build_repo_target(tmp_path)
    h = _NoopHarness()
    result = await h.scan(target)
    assert result.findings == []
