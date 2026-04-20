"""MCP server exposing ``s0-cli`` as tools to AI assistants.

Anything that speaks the Model Context Protocol (Claude Desktop, Claude
Code, Cursor, Continue, Zed, etc.) can run this server and let its agent
scan code with `s0` directly — no manual copy-pasting of CLI output.

Run it manually for debugging::

    s0-mcp                # stdio transport (default)
    python -m s0_cli.mcp_server

Or wire it into an MCP client; see ``docs/integrations/INSTALL.md`` for
config snippets.

Design notes
------------

* **Subprocess, not in-process.** Each scan spawns a fresh ``s0`` so the
  server is decoupled from harness state, doesn't leak file handles
  across requests, and crashes in the inner harness can't take the MCP
  server down with them.
* **JSON over a temp file**, not stdout. ``s0 scan`` prints progress
  events / banners to stdout; we keep the JSON separate via ``--out`` so
  we don't have to filter the stream.
* **`no_llm=True` is the default.** AI assistants already have an LLM
  budget; making them pay twice (once for the assistant, once for s0
  triage) is rarely what the user wants. They can opt into LLM triage
  explicitly when they need richer rationales.
* **Bounded output.** We cap returned findings at ``MAX_FINDINGS`` (200
  by default) so a noisy raw scan doesn't blow past the model's context
  window. The full report is still on disk at the path we return.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover - import error path
    raise SystemExit(
        "s0-mcp requires the optional `mcp` dependency.\n"
        "Install it with:  uv pip install 's0-cli[mcp]'  "
        "or  pip install 'mcp>=1.2'"
    ) from exc

DEFAULT_TIMEOUT = 600.0  # 10 min — semgrep on a big repo can crawl
MAX_FINDINGS = 200


mcp = FastMCP(
    "s0-cli",
    instructions=(
        "Use s0-cli when the user asks to audit, scan, find vulnerabilities, "
        "check for security issues, or look for 'vibe-code' problems "
        "(stub auth, hallucinated imports, dummy crypto, prompt-injection "
        "sinks) in source code. Prefer `scan_path` for a directory or file "
        "and `scan_diff` for a git range / PR. Both default to no-LLM mode "
        "(fast, deterministic) — only set `no_llm=False` if the user "
        "explicitly asks for LLM triage and explanations."
    ),
)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _s0_cmd() -> list[str]:
    """Locate the ``s0`` CLI.

    Prefer the ``s0`` binary on $PATH (works for ``uv tool install``,
    ``pipx install``, plain ``pip install``). Fall back to invoking the
    package as a module with the current Python — which works when the
    MCP server is launched from a project venv that has s0-cli installed
    editable.
    """
    s0 = shutil.which("s0")
    if s0:
        return [s0]
    return [sys.executable, "-m", "s0_cli"]


async def _run_s0(
    args: list[str],
    *,
    cwd: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Invoke ``s0`` and return its parsed JSON report.

    Always appends ``--format json --out <tempfile> --quiet`` so we
    capture machine-readable output independent of stdout chatter.
    """
    out_fd, out_path = tempfile.mkstemp(suffix=".json", prefix="s0-mcp-")
    os.close(out_fd)
    try:
        cmd = [
            *_s0_cmd(),
            *args,
            "--format",
            "json",
            "--out",
            out_path,
            "--quiet",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
                await proc.wait()
            return {
                "ok": False,
                "error": f"s0 timed out after {int(timeout)}s",
                "command": " ".join(cmd),
            }

        # `s0 scan` returns 0 normally, non-zero only when --fail-on triggers.
        # The MCP wrapper always passes `--fail-on never`, so anything non-zero
        # here is a real failure (missing scanner, bad path, etc).
        if proc.returncode not in (0,):
            return {
                "ok": False,
                "error": f"s0 exited with code {proc.returncode}",
                "stderr": stderr.decode("utf-8", "replace")[-2000:],
                "stdout": stdout.decode("utf-8", "replace")[-500:],
                "command": " ".join(cmd),
            }

        try:
            data = json.loads(Path(out_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            return {
                "ok": False,
                "error": f"failed to parse s0 JSON output: {e}",
                "stderr": stderr.decode("utf-8", "replace")[-2000:],
            }

        findings = data.get("findings", [])
        truncated = len(findings) > MAX_FINDINGS
        # When truncated, leak the temp file on purpose so the caller can
        # grab the full report at `report_path`. Otherwise clean up below.
        keep_file = truncated
        report_path = out_path if truncated else None
        return {
            "ok": True,
            "count": len(findings),
            "findings": findings[:MAX_FINDINGS],
            "truncated": truncated,
            "max_findings_returned": MAX_FINDINGS if truncated else len(findings),
            "report_path": report_path,
            "stderr_tail": (stderr.decode("utf-8", "replace")[-500:] or None),
        }
    finally:
        # `keep_file` is set on the success path when we want the file to
        # outlive the response. Any other exit (timeout, parse error,
        # subprocess failure) cleans up.
        if not locals().get("keep_file"):
            with contextlib.suppress(OSError):
                os.unlink(out_path)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def scan_path(
    path: str,
    no_llm: bool = True,
    scanners: list[str] | None = None,
    exclude_scanners: list[str] | None = None,
    harness: str | None = None,
) -> dict[str, Any]:
    """Scan a directory or single file for security and vibe-code issues.

    Runs the s0-cli hybrid pipeline (semgrep + bandit + ruff + gitleaks +
    trivy + LLM detectors) on ``path`` and returns the deduplicated
    finding list as JSON.

    Args:
        path: Absolute or repo-relative path to scan. Files and directories
            both work; directories are scanned recursively.
        no_llm: When true (default), skip the LLM triage step. Faster,
            deterministic, and free. Set to false if the caller explicitly
            wants LLM-generated severity recalibration and natural-language
            explanations (requires a provider API key in the environment).
        scanners: Optional whitelist of scanner names to run (e.g.
            ``["bandit", "ruff"]``). Use ``list_scanners`` to discover
            valid names.
        exclude_scanners: Optional list of scanner names to skip (e.g.
            ``["trivy"]`` to skip slow container scans).
        harness: Optional named harness override (advanced; defaults to
            the production harness).

    Returns:
        ``{ok, count, findings[], truncated, max_findings_returned}``.
        Each finding has ``path``, ``line``, ``severity``, ``rule_id``,
        ``message``, and (when available) ``cwe`` / ``why`` / ``fix``.
    """
    args = ["scan", path, "--fail-on", "never"]
    if no_llm:
        args.append("--no-llm")
    for s in scanners or []:
        args.extend(["--scanner", s])
    for s in exclude_scanners or []:
        args.extend(["--exclude-scanner", s])
    if harness:
        args.extend(["--harness", harness])
    return await _run_s0(args)


@mcp.tool()
async def scan_diff(
    repo_path: str,
    base: str = "HEAD~1",
    head: str = "HEAD",
    no_llm: bool = True,
) -> dict[str, Any]:
    """Scan only the lines changed between two git refs.

    Ideal for PR reviews: runs the same hybrid pipeline as ``scan_path``
    but restricts findings to hunks touched in the diff so reviewers
    aren't drowning in pre-existing issues.

    Args:
        repo_path: Path to the git repository to scan inside.
        base: Base ref of the diff (default ``HEAD~1`` — the previous commit).
        head: Head ref of the diff (default ``HEAD``).
        no_llm: See ``scan_path``.

    Returns:
        Same shape as ``scan_path``.
    """
    args = ["scan", "--diff", f"{base}..{head}", "--fail-on", "never"]
    if no_llm:
        args.append("--no-llm")
    return await _run_s0(args, cwd=repo_path)


@mcp.tool()
def list_scanners() -> dict[str, Any]:
    """List the deterministic + LLM scanners s0-cli ships with.

    No subprocess — the registry is read directly from the package so
    this is instant and works even if ``s0`` isn't on PATH yet.
    """
    from s0_cli.scanners import REGISTRY

    descriptions = {
        "semgrep": "Semgrep with the security-audit + secrets rulesets",
        "bandit": "Bandit (Python AST-based security linter)",
        "ruff": "Ruff's `S` (security) rule set",
        "gitleaks": "Gitleaks for committed secrets",
        "trivy": "Trivy filesystem scan (vuln'd dependencies, IaC, config)",
        "hallucinated_import": "LLM detector for imports that don't exist on PyPI / npm",
        "supply_chain": "OSV-Scanner + OpenSSF Scorecard + guarddog (CVEs, repo trust, malicious packages)",
        "vibe_llm": "LLM detector for stub auth, dummy crypto, prompt-injection sinks",
    }
    return {
        "scanners": [
            {"name": name, "description": descriptions.get(name, "")}
            for name in sorted(REGISTRY)
        ],
    }


@mcp.tool()
def list_harnesses() -> dict[str, Any]:
    """List harnesses bundled with s0-cli.

    Most callers don't need this — the production harness is the
    default. Useful for advanced users running A/B tests or pinning to
    a specific harness for reproducibility.
    """
    harnesses_dir = Path(__file__).parent / "harnesses"
    if not harnesses_dir.is_dir():
        return {"harnesses": []}
    names = sorted(
        p.stem
        for p in harnesses_dir.glob("*.py")
        if p.stem != "__init__" and not p.stem.startswith("_")
    )
    return {"harnesses": names}


# ---------------------------------------------------------------------------
# Entrypoints
# ---------------------------------------------------------------------------


def main() -> None:
    """Console-script entrypoint (``s0-mcp``). Runs stdio transport."""
    mcp.run()


if __name__ == "__main__":
    main()
