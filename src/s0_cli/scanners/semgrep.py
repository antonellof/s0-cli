"""semgrep scanner integration.

Runs `semgrep --json --config auto` (or a configured ruleset) against the target,
parses the output into normalized `Finding` objects.

Exits cleanly with [] when semgrep is missing; `is_available()` is the gate.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from s0_cli.scanners.base import Finding, ScannerError, Severity
from s0_cli.targets.base import Target, TargetMode

_SEVERITY_MAP: dict[str, Severity] = {
    "INFO": "info",
    "LOW": "low",
    "WARNING": "medium",
    "MEDIUM": "medium",
    "ERROR": "high",
    "HIGH": "high",
    "CRITICAL": "critical",
}


class SemgrepScanner:
    name = "semgrep"

    def is_available(self) -> bool:
        return shutil.which("semgrep") is not None

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
            raise ScannerError("semgrep timed out") from e

        if proc.returncode not in (0, 1) and not proc.stdout.strip():
            raise ScannerError(
                f"semgrep failed (exit {proc.returncode}): {proc.stderr.strip()[:400]}"
            )

        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as e:
            raise ScannerError(f"semgrep emitted invalid JSON: {e}") from e

        return parse_semgrep_json(data, root=target.root)

    DEFAULT_CONFIGS: tuple[str, ...] = (
        "p/security-audit",
        "p/secrets",
        "p/owasp-top-ten",
    )

    def _build_command(self, target: Target) -> list[str]:
        cmd = [
            "semgrep",
            "scan",
            "--json",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
        ]
        for cfg in self.DEFAULT_CONFIGS:
            cmd.extend(["--config", cfg])
        if target.mode == TargetMode.FILE and target.files:
            for f in target.files:
                cmd.append(str(f))
        else:
            cmd.append(str(target.root))
        return cmd


def parse_semgrep_json(data: dict[str, Any], root: Path | None = None) -> list[Finding]:
    """Parse semgrep's JSON output into normalized Findings.

    Accepts both `data["results"]` (modern semgrep) and `data["matches"]`
    (older builds), defaults to the former. When `root` is provided, absolute
    paths emitted by semgrep are rewritten to be relative to `root`.
    """
    out: list[Finding] = []
    results = data.get("results") or data.get("matches") or []
    for r in results:
        check_id = r.get("check_id") or r.get("rule_id") or "unknown"
        path = r.get("path") or r.get("location", {}).get("path", "?")
        path = _normalize_to_root(path, root)
        start = r.get("start", {}) or {}
        end = r.get("end", {}) or {}
        line = int(start.get("line") or 0)
        end_line = int(end.get("line") or line)

        extra = r.get("extra", {}) or {}
        sev_raw = (extra.get("severity") or r.get("severity") or "WARNING").upper()
        severity = _SEVERITY_MAP.get(sev_raw, "medium")

        message = (extra.get("message") or r.get("message") or check_id).strip()

        snippet = (extra.get("lines") or "").strip() or None
        if not snippet or snippet == "requires login":
            snippet = _read_snippet(root, path, line, end_line)
        if snippet and len(snippet) > 1000:
            snippet = snippet[:1000] + "..."

        cwe_field = extra.get("metadata", {}).get("cwe", []) if extra.get("metadata") else []
        if isinstance(cwe_field, str):
            cwe_field = [cwe_field]
        cwe = tuple(c for c in cwe_field if c)

        out.append(
            Finding(
                rule_id=check_id,
                severity=severity,
                path=path,
                line=line,
                end_line=end_line,
                message=message,
                source="semgrep",
                cwe=cwe,
                snippet=snippet,
                confidence=1.0,
                raw=r,
            )
        )
    return out


def _read_snippet(root: Path | None, rel_path: str, line: int, end_line: int) -> str | None:
    """Read a small window of source around a finding's line range."""
    if line <= 0:
        return None
    candidates: list[Path] = []
    if root is not None:
        candidates.append((root / rel_path).resolve())
    candidates.append(Path(rel_path))
    for p in candidates:
        if not p.is_file():
            continue
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        start = max(0, line - 1)
        stop = min(len(lines), max(end_line, line))
        return "\n".join(lines[start:stop])
    return None


def _normalize_to_root(path: str, root: Path | None) -> str:
    """Rewrite absolute paths to be relative to `root` when possible.

    Semgrep prints absolute paths when invoked with an absolute target.
    The scorer matches on relative paths, and the LLM should see relative
    paths so it can `read_file("foo.py")` directly through the tool layer.
    """
    if not path or root is None:
        return path
    p = Path(path)
    if not p.is_absolute():
        return str(p)
    try:
        return str(p.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(p)
