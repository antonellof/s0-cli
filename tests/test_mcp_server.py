"""Tests for the MCP server.

These tests exercise the MCP layer end-to-end:

- Tool registration: every advertised tool is reachable via FastMCP's
  internal tool manager (so the JSON-RPC `tools/list` will surface it).
- Pure tools: ``list_scanners`` and ``list_harnesses`` are smoke-tested
  directly — they don't shell out, so they're fast and deterministic.
- Subprocess tools: ``scan_path`` is tested via a fake ``s0`` binary
  that writes a known JSON file. We patch ``shutil.which`` so the MCP
  server picks up the fake instead of the real one — keeps tests
  hermetic and fast (no semgrep / bandit invocation).

We deliberately don't run the real ``s0 scan`` here — that's covered by
the existing eval / runner tests. This file's job is to verify the MCP
contract.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from s0_cli import mcp_server as srv

# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_all_expected_tools_are_registered():
    """`tools/list` over JSON-RPC must surface every tool we ship."""
    tools = await srv.mcp.list_tools()
    names = {t.name for t in tools}
    assert names == {"scan_path", "scan_diff", "list_scanners", "list_harnesses"}


@pytest.mark.asyncio
async def test_scan_path_schema_has_expected_args():
    tools = await srv.mcp.list_tools()
    scan_path = next(t for t in tools if t.name == "scan_path")
    props = scan_path.inputSchema["properties"]
    assert set(props) >= {"path", "no_llm", "scanners", "exclude_scanners", "harness"}
    # `path` is required, the rest have defaults.
    assert scan_path.inputSchema["required"] == ["path"]


@pytest.mark.asyncio
async def test_scan_path_default_no_llm_is_true():
    """LLM-on-by-default would silently bill assistants twice — guard it."""
    tools = await srv.mcp.list_tools()
    scan_path = next(t for t in tools if t.name == "scan_path")
    assert scan_path.inputSchema["properties"]["no_llm"]["default"] is True

    diff_tool = next(t for t in tools if t.name == "scan_diff")
    assert diff_tool.inputSchema["properties"]["no_llm"]["default"] is True


# ---------------------------------------------------------------------------
# Pure tools (no subprocess)
# ---------------------------------------------------------------------------


def test_list_scanners_returns_known_registry():
    result = srv.list_scanners()
    names = [s["name"] for s in result["scanners"]]
    # Don't pin the full list — the registry is intentionally extensible —
    # but the core five SAST + two LLM detectors should all be there.
    assert {"semgrep", "bandit", "ruff", "gitleaks", "trivy"} <= set(names)
    assert {"hallucinated_import", "vibe_llm"} <= set(names)
    # Each scanner has a non-empty human-readable description.
    for s in result["scanners"]:
        assert s["description"]


def test_list_harnesses_returns_python_files():
    result = srv.list_harnesses()
    assert "harnesses" in result
    # baseline_v0 ships out of the box.
    assert any("baseline" in h for h in result["harnesses"])


# ---------------------------------------------------------------------------
# scan_path / scan_diff via a fake `s0` binary
# ---------------------------------------------------------------------------


def _write_fake_s0(tmp_path: Path, payload: dict, exit_code: int = 0) -> Path:
    """Create a small Python script that mimics `s0 scan`.

    It parses ``--out <file>`` from its args, writes ``payload`` there as
    JSON, and exits with ``exit_code``. That's the entire contract the
    MCP server depends on, so a 20-line shim is enough.
    """
    script = tmp_path / "fake_s0"
    body = textwrap.dedent(
        f"""\
        #!{sys.executable}
        import json, sys
        args = sys.argv[1:]
        out_path = None
        if "--out" in args:
            out_path = args[args.index("--out") + 1]
        if out_path:
            with open(out_path, "w") as f:
                json.dump({json.dumps(payload)}, f)
        sys.exit({exit_code})
        """
    )
    script.write_text(body)
    script.chmod(0o755)
    return script


@pytest.mark.asyncio
async def test_scan_path_returns_findings_via_fake_s0(tmp_path: Path):
    payload = {
        "version": "0.0.1",
        "count": 2,
        "findings": [
            {
                "path": "src/auth.py",
                "line": 10,
                "severity": "high",
                "rule_id": "B602",
                "message": "subprocess shell=True",
                "source": "bandit",
            },
            {
                "path": "src/auth.py",
                "line": 14,
                "severity": "medium",
                "rule_id": "B301",
                "message": "pickle.loads on untrusted input",
                "source": "bandit",
            },
        ],
    }
    fake = _write_fake_s0(tmp_path, payload)

    with patch.object(srv.shutil, "which", return_value=str(fake)):
        result = await srv.scan_path(path="/tmp/anywhere", no_llm=True)

    assert result["ok"] is True
    assert result["count"] == 2
    assert result["truncated"] is False
    assert result["findings"][0]["rule_id"] == "B602"
    assert result["findings"][1]["severity"] == "medium"


@pytest.mark.asyncio
async def test_scan_path_truncates_at_max_findings(tmp_path: Path, monkeypatch):
    """Huge result sets must be capped so we don't blow the model's context."""
    monkeypatch.setattr(srv, "MAX_FINDINGS", 3)
    payload = {
        "findings": [
            {"path": f"f{i}.py", "line": i, "severity": "low", "rule_id": "X", "message": "m"}
            for i in range(10)
        ]
    }
    fake = _write_fake_s0(tmp_path, payload)

    with patch.object(srv.shutil, "which", return_value=str(fake)):
        result = await srv.scan_path(path="/tmp/anywhere")

    assert result["count"] == 10
    assert result["truncated"] is True
    assert len(result["findings"]) == 3
    assert result["max_findings_returned"] == 3
    # When truncated, the full report is preserved on disk.
    assert result["report_path"]
    assert Path(result["report_path"]).exists()
    # Cleanup so we don't leak temp files between tests.
    os.unlink(result["report_path"])


@pytest.mark.asyncio
async def test_scan_path_propagates_subprocess_failure(tmp_path: Path):
    """A non-zero exit from `s0` should surface as ``ok=False`` with stderr."""
    fake = _write_fake_s0(tmp_path, payload={}, exit_code=2)

    with patch.object(srv.shutil, "which", return_value=str(fake)):
        result = await srv.scan_path(path="/nonexistent")

    assert result["ok"] is False
    assert "exited with code 2" in result["error"]


@pytest.mark.asyncio
async def test_scan_path_passes_through_scanner_filters(tmp_path: Path):
    """`scanners` and `exclude_scanners` must reach the CLI as repeated flags."""
    captured: list[list[str]] = []

    real_create = asyncio.create_subprocess_exec

    async def spy_create(*args, **kwargs):
        captured.append(list(args))
        return await real_create(*args, **kwargs)

    fake = _write_fake_s0(tmp_path, payload={"findings": []})

    with (
        patch.object(srv.shutil, "which", return_value=str(fake)),
        patch.object(srv.asyncio, "create_subprocess_exec", spy_create),
    ):
        await srv.scan_path(
            path="/tmp/x",
            scanners=["bandit", "ruff"],
            exclude_scanners=["trivy"],
        )

    assert captured, "subprocess was never spawned"
    cmd = captured[0]
    # Repeated --scanner / --exclude-scanner flags.
    assert cmd.count("--scanner") == 2
    assert "bandit" in cmd and "ruff" in cmd
    assert cmd.count("--exclude-scanner") == 1
    assert "trivy" in cmd


@pytest.mark.asyncio
async def test_scan_diff_runs_in_repo_path(tmp_path: Path):
    """`scan_diff` must pass cwd=repo_path so git-diff resolution is correct."""
    captured = {}

    real_create = asyncio.create_subprocess_exec

    async def spy_create(*args, **kwargs):
        captured["cwd"] = kwargs.get("cwd")
        captured["args"] = list(args)
        return await real_create(*args, **kwargs)

    fake = _write_fake_s0(tmp_path, payload={"findings": []})
    repo_path = tmp_path / "fake-repo"
    repo_path.mkdir()

    with (
        patch.object(srv.shutil, "which", return_value=str(fake)),
        patch.object(srv.asyncio, "create_subprocess_exec", spy_create),
    ):
        await srv.scan_diff(repo_path=str(repo_path), base="main", head="HEAD")

    assert captured["cwd"] == str(repo_path)
    assert "--diff" in captured["args"]
    assert "main..HEAD" in captured["args"]


# ---------------------------------------------------------------------------
# Server metadata
# ---------------------------------------------------------------------------


def test_server_has_instructions_for_the_model():
    """The `instructions` block is what tells assistants WHEN to use this server."""
    assert srv.mcp.instructions
    # Spot-check the intent is conveyed.
    inst = srv.mcp.instructions.lower()
    assert "vulnerab" in inst or "security" in inst
    assert "scan" in inst


def test_main_entrypoint_is_callable():
    """The console-script entry must resolve to a real callable."""
    assert callable(srv.main)
