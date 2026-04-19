"""trivy scanner integration (filesystem mode: deps + IaC + secrets).

Runs `trivy fs --format json --quiet --scanners vuln,secret,misconfig <target>`
and normalizes Vulnerabilities, Secrets, and Misconfigurations into Findings.

Trivy can also scan container images and git repos; we deliberately wire up
only the filesystem scanner — the same one a developer would run pre-commit
on a checked-out source tree.
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
)
from s0_cli.targets.base import Target

_TRIVY_SEVERITY: dict[str, Severity] = {
    "UNKNOWN": "low",
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}


class TrivyScanner:
    name = "trivy"

    def is_available(self) -> bool:
        return shutil.which("trivy") is not None

    def run(self, target: Target) -> list[Finding]:
        if not self.is_available():
            return []
        cmd = [
            "trivy", "fs",
            "--format", "json",
            "--quiet",
            "--scanners", "vuln,secret,misconfig",
            "--exit-code", "0",
            str(target.root),
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise ScannerError("trivy timed out") from e

        if proc.returncode != 0 and not proc.stdout.strip():
            raise ScannerError(
                f"trivy failed (exit {proc.returncode}): {proc.stderr.strip()[:400]}"
            )

        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as e:
            raise ScannerError(f"trivy emitted invalid JSON: {e}") from e

        return parse_trivy_json(data, root=target.root)


def parse_trivy_json(data: dict[str, Any], root: Path | None = None) -> list[Finding]:
    """Parse trivy's JSON output into normalized Findings.

    Trivy organizes results per "Target" (a file/directory) with subarrays
    `Vulnerabilities`, `Secrets`, `Misconfigurations`. We flatten across all
    targets.
    """
    out: list[Finding] = []
    for tgt in data.get("Results") or []:
        path = normalize_to_root(tgt.get("Target") or "?", root)

        for v in tgt.get("Vulnerabilities") or []:
            sev_raw = (v.get("Severity") or "UNKNOWN").upper()
            severity = _TRIVY_SEVERITY.get(sev_raw, "medium")
            cve = v.get("VulnerabilityID") or "trivy-unknown"
            pkg = v.get("PkgName") or "?"
            installed = v.get("InstalledVersion") or "?"
            fixed = v.get("FixedVersion") or "(no fix)"
            message = (v.get("Title") or v.get("Description") or cve).strip()
            cwe_field = v.get("CweIDs") or []
            cwe = tuple(c for c in cwe_field if c)
            out.append(
                Finding(
                    rule_id=str(cve),
                    severity=severity,
                    path=path,
                    line=0,
                    message=f"{cve} in {pkg} {installed}: {message} (fix: {fixed})",
                    source="trivy",
                    cwe=cwe,
                    snippet=None,
                    confidence=1.0,
                    raw=v,
                )
            )

        for s in tgt.get("Secrets") or []:
            line = int(s.get("StartLine") or 0)
            end_line = int(s.get("EndLine") or line)
            severity_raw = (s.get("Severity") or "HIGH").upper()
            severity = _TRIVY_SEVERITY.get(severity_raw, "high")
            rid = s.get("RuleID") or "trivy-secret-unknown"
            out.append(
                Finding(
                    rule_id=str(rid),
                    severity=severity,
                    path=path,
                    line=line,
                    end_line=end_line,
                    message=(s.get("Title") or s.get("Match") or rid).strip(),
                    source="trivy",
                    cwe=("CWE-798",),
                    snippet=(s.get("Match") or "").strip() or None,
                    confidence=0.9,
                    raw=s,
                )
            )

        for m in tgt.get("Misconfigurations") or []:
            severity_raw = (m.get("Severity") or "MEDIUM").upper()
            severity = _TRIVY_SEVERITY.get(severity_raw, "medium")
            rid = m.get("ID") or "trivy-misconfig-unknown"
            cause = m.get("CauseMetadata") or {}
            line = int(cause.get("StartLine") or 0)
            end_line = int(cause.get("EndLine") or line)
            out.append(
                Finding(
                    rule_id=str(rid),
                    severity=severity,
                    path=path,
                    line=line,
                    end_line=end_line,
                    message=(m.get("Title") or m.get("Description") or rid).strip(),
                    source="trivy",
                    snippet=None,
                    confidence=0.9,
                    raw=m,
                )
            )
    return out
