"""bandit scanner integration.

Runs `bandit -f json -r <target>` (or per-file in FILE mode) and parses
output into normalized `Finding` objects.

Bandit's exit codes: 0 = no issues, 1 = issues found, 2 = config error,
others = bandit error. We accept (0, 1) as success when stdout has JSON.
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

_BANDIT_SEVERITY: dict[str, Severity] = {
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
}

_BANDIT_CONFIDENCE: dict[str, float] = {
    "LOW": 0.4,
    "MEDIUM": 0.7,
    "HIGH": 1.0,
}


class BanditScanner:
    name = "bandit"

    def is_available(self) -> bool:
        return shutil.which("bandit") is not None

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
                timeout=300,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise ScannerError("bandit timed out") from e

        # bandit exits 1 when issues found, 0 when none. >1 is a real error,
        # but only fail if we have nothing parseable in stdout.
        if proc.returncode not in (0, 1) and not proc.stdout.strip():
            raise ScannerError(
                f"bandit failed (exit {proc.returncode}): {proc.stderr.strip()[:400]}"
            )

        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as e:
            raise ScannerError(f"bandit emitted invalid JSON: {e}") from e

        return parse_bandit_json(data, root=target.root)

    def _build_command(self, target: Target) -> list[str]:
        cmd = ["bandit", "-f", "json", "-q"]
        if target.mode == TargetMode.FILE and target.files:
            for f in target.files:
                cmd.append(str(f))
        else:
            cmd.extend(["-r", str(target.root)])
        return cmd


def parse_bandit_json(data: dict[str, Any], root: Path | None = None) -> list[Finding]:
    """Parse bandit's JSON output into normalized Findings."""
    out: list[Finding] = []
    for r in data.get("results") or []:
        rule_id = r.get("test_id") or r.get("test_name") or "unknown"
        path = normalize_to_root(r.get("filename") or "?", root)
        line = int(r.get("line_number") or 0)
        end_line = int(r.get("end_col_offset") or 0) if r.get("line_range") else line
        # bandit's `line_range` is a list of int line numbers
        line_range = r.get("line_range") or []
        if line_range:
            end_line = max(line_range)

        sev_raw = (r.get("issue_severity") or "MEDIUM").upper()
        severity = _BANDIT_SEVERITY.get(sev_raw, "medium")

        conf_raw = (r.get("issue_confidence") or "MEDIUM").upper()
        confidence = _BANDIT_CONFIDENCE.get(conf_raw, 0.7)

        message = (r.get("issue_text") or "").strip() or rule_id

        snippet = (r.get("code") or "").strip() or None
        if not snippet:
            snippet = read_snippet(root, path, line, end_line)
        if snippet and len(snippet) > 1000:
            snippet = snippet[:1000] + "..."

        cwe_field = r.get("issue_cwe", {}) or {}
        cwe_id = cwe_field.get("id")
        cwe = (f"CWE-{cwe_id}",) if cwe_id else ()

        out.append(
            Finding(
                rule_id=str(rule_id),
                severity=severity,
                path=path,
                line=line,
                end_line=end_line,
                message=message,
                source="bandit",
                cwe=cwe,
                snippet=snippet,
                confidence=confidence,
                raw=r,
            )
        )
    return out
