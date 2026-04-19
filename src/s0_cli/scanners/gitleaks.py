"""gitleaks scanner integration (secret detection).

Runs `gitleaks detect --no-git --report-format json --report-path -` against
the target directory and parses the output. Targets `--no-git` mode so it
also works on non-git folders (e.g. extracted tarballs the user is reviewing).
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


class GitleaksScanner:
    name = "gitleaks"

    def is_available(self) -> bool:
        return shutil.which("gitleaks") is not None

    def run(self, target: Target) -> list[Finding]:
        if not self.is_available():
            return []
        if target.mode == TargetMode.FILE:
            # gitleaks scans directories; for explicit file lists, scan parents.
            roots = sorted({f.parent for f in (target.files or [])})
            findings: list[Finding] = []
            for r in roots:
                findings.extend(self._run_one(r, target.root))
            return findings
        return self._run_one(target.root, target.root)

    def _run_one(self, scan_dir: Path, label_root: Path) -> list[Finding]:
        cmd = [
            "gitleaks",
            "detect",
            "--no-git",
            "--no-banner",
            "--report-format", "json",
            "--report-path", "/dev/stdout",
            "--source", str(scan_dir),
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise ScannerError("gitleaks timed out") from e

        # gitleaks exits 1 when leaks are found, 0 when not. Both are success.
        if proc.returncode not in (0, 1):
            stderr = proc.stderr.strip()[:400]
            if not proc.stdout.strip():
                raise ScannerError(f"gitleaks failed (exit {proc.returncode}): {stderr}")

        # gitleaks JSON output is an array. May be empty/null when no leaks.
        raw_out = (proc.stdout or "").strip()
        if not raw_out or raw_out in ("null", "[]"):
            return []
        try:
            data = json.loads(raw_out)
        except json.JSONDecodeError as e:
            # gitleaks sometimes prints a banner before the JSON; try to recover
            # by trimming up to the first '['.
            idx = raw_out.find("[")
            if idx >= 0:
                try:
                    data = json.loads(raw_out[idx:])
                except json.JSONDecodeError as e2:
                    raise ScannerError(f"gitleaks emitted invalid JSON: {e2}") from e2
            else:
                raise ScannerError(f"gitleaks emitted invalid JSON: {e}") from e

        return parse_gitleaks_json(data, root=label_root)


def parse_gitleaks_json(data: list[dict[str, Any]], root: Path | None = None) -> list[Finding]:
    """Parse gitleaks' JSON output into normalized Findings.

    Gitleaks always reports secrets as `high` severity in our taxonomy. CWE-798
    (use of hard-coded credentials) is the canonical mapping.
    """
    out: list[Finding] = []
    for r in data or []:
        rule_id = r.get("RuleID") or r.get("Rule") or "gitleaks-unknown"
        path = normalize_to_root(r.get("File") or "?", root)
        line = int(r.get("StartLine") or 0)
        end_line = int(r.get("EndLine") or line)

        severity: Severity = "high"
        message = (r.get("Description") or rule_id).strip()
        secret = (r.get("Secret") or "").strip()
        if secret:
            redacted = secret[:4] + "***" + secret[-2:] if len(secret) > 8 else "***"
            message = f"{message} (matched: {redacted})"

        snippet = (r.get("Match") or "").strip() or None
        if snippet and len(snippet) > 200:
            snippet = snippet[:200] + "..."
        if not snippet:
            snippet = read_snippet(root, path, line, end_line)

        out.append(
            Finding(
                rule_id=str(rule_id),
                severity=severity,
                path=path,
                line=line,
                end_line=end_line,
                message=message,
                source="gitleaks",
                cwe=("CWE-798",),
                snippet=snippet,
                confidence=0.9,
                raw=r,
            )
        )
    return out
