"""ruff scanner integration (security subset).

Runs `ruff check --select S,B --output-format json <target>` to surface ruff's
flake8-bandit (S) and bugbear (B) families without all the style noise. This
is a cheap, fast complement to bandit that catches a few additional patterns
(asserts in production, hardcoded passwords, jinja autoescape off, etc.).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from s0_cli.scanners.base import (
    Finding,
    ScannerError,
    Severity,
    normalize_to_root,
    read_snippet,
)
from s0_cli.targets.base import Target, TargetMode

_RULE_SEVERITY: dict[str, Severity] = {
    "S": "medium",
    "B": "low",
}

_HIGH_RULES = {
    "S105", "S106", "S107",  # hardcoded passwords / function args
    "S301", "S302", "S307",  # pickle / marshal / eval
    "S324",                  # md5/sha1
    "S501", "S502", "S503", "S504", "S505",  # ssl issues
    "S601", "S602", "S605", "S606", "S607",  # shell + subprocess
    "S608",                  # SQL injection (string-formatted query)
}


class RuffScanner:
    name = "ruff"

    def is_available(self) -> bool:
        return shutil.which("ruff") is not None

    def run(self, target: Target) -> list[Finding]:
        if not self.is_available():
            return []
        cmd = self._build_command(target)
        try:
            proc = subprocess.run(
                cmd,
                cwd=target.root,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise ScannerError("ruff timed out") from e

        # ruff exits 1 when issues found, 0 when none. Anything else with no
        # JSON in stdout is a config or invocation problem.
        if proc.returncode not in (0, 1) and not proc.stdout.strip():
            raise ScannerError(
                f"ruff failed (exit {proc.returncode}): {proc.stderr.strip()[:400]}"
            )

        try:
            data = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError as e:
            raise ScannerError(f"ruff emitted invalid JSON: {e}") from e

        return parse_ruff_json(data, root=target.root)

    def _build_command(self, target: Target) -> list[str]:
        cmd = [
            "ruff",
            "check",
            "--select", "S,B",
            "--output-format", "json",
            "--no-cache",
        ]
        if target.mode == TargetMode.FILE and target.files:
            for f in target.files:
                cmd.append(str(f))
        else:
            cmd.append(str(target.root))
        return cmd


def parse_ruff_json(data: list[dict[str, Any]], root: Path | None = None) -> list[Finding]:
    """Parse ruff's JSON output into normalized Findings.

    ruff emits a top-level JSON array.
    """
    out: list[Finding] = []
    for r in data:
        code = r.get("code") or "unknown"
        family = code[:1] if code else ""
        severity = _RULE_SEVERITY.get(family, "low")
        if code in _HIGH_RULES:
            severity = "high"

        path = normalize_to_root(r.get("filename") or "?", root)
        location = r.get("location") or {}
        end_loc = r.get("end_location") or location
        line = int(location.get("row") or 0)
        end_line = int(end_loc.get("row") or line)

        message = (r.get("message") or code).strip()
        snippet = read_snippet(root, path, line, end_line)
        if snippet and len(snippet) > 1000:
            snippet = snippet[:1000] + "..."

        out.append(
            Finding(
                rule_id=str(code),
                severity=severity,
                path=path,
                line=line,
                end_line=end_line,
                message=message,
                source="ruff",
                snippet=snippet,
                confidence=0.8 if family == "S" else 0.5,
                raw=r,
            )
        )
    return out
