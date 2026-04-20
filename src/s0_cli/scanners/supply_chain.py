"""Supply-chain risk scanner: OSV-Scanner + OpenSSF Scorecard + guarddog.

A composite detector that goes *beyond* CVE matching (which Trivy already
covers) to surface the kinds of supply-chain risk that don't yet have a
CVE assigned:

  - **OSV-Scanner** (Google, OSS): broader CVE/GHSA coverage than Trivy
    for OSS lockfiles (pip, npm, cargo, go, maven, gradle, composer, ...).
    Queries osv.dev directly. Catches advisories Trivy misses.

  - **OpenSSF Scorecard** (OSS, optional): when the target is a GitHub
    repo, surfaces *trustworthiness* signals — unsigned releases, no
    branch protection, no fuzzing, dead maintainers, missing security
    policy, dependency-update bots disabled. None of these are CVEs;
    all of them predict future supply-chain incidents.

  - **guarddog** (DataDog, OSS, optional): heuristics for *actively
    malicious* PyPI / npm packages — install-time exec, exfil endpoints
    in setup.py, typosquats, base64-encoded payloads. Catches packages
    that ARE the attack rather than merely have one.

Every backend is independently optional; the scanner is "available" if
at least one backend is installed. Missing backends are silently skipped
(consistent with how `s0 scanners` reports per-tool availability).

CWE mapping:
  - OSV vulnerabilities -> CWE the OSV record reports, otherwise CWE-1104
    (Use of Unmaintained Third Party Components).
  - Scorecard low-score checks -> CWE-1357 (Insufficient Trust).
  - guarddog malicious-pkg matches -> CWE-506 (Embedded Malicious Code).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from s0_cli.scanners.base import (
    Finding,
    Severity,
    normalize_to_root,
)
from s0_cli.targets.base import Target

_OSV_SEVERITY: dict[str, Severity] = {
    "UNKNOWN": "low",
    "LOW": "low",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}

# Files OSV-Scanner can interpret (it can also walk a directory; this list
# is used only for fast-path detection of "does this target even have a
# lockfile worth scanning?" so we don't shell out for nothing).
_OSV_LOCKFILES = (
    "requirements.txt", "Pipfile.lock", "poetry.lock", "uv.lock",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Cargo.lock", "go.sum", "go.mod",
    "composer.lock", "Gemfile.lock", "gradle.lockfile",
    "pom.xml",
)

_SCORECARD_THRESHOLD = 3  # checks scoring <=3 surface as findings.


class SupplyChainScanner:
    """Aggregates osv-scanner + scorecard + guarddog when present."""

    name = "supply_chain"

    def is_available(self) -> bool:
        # Scanner is "available" if any backend is callable. The individual
        # `_run_*` methods short-circuit if their binary is missing.
        return any(
            shutil.which(b) for b in ("osv-scanner", "scorecard", "guarddog")
        )

    def run(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        if shutil.which("osv-scanner"):
            findings.extend(_run_osv(target))
        if shutil.which("scorecard"):
            findings.extend(_run_scorecard(target))
        if shutil.which("guarddog"):
            findings.extend(_run_guarddog(target))
        return findings


# ---------------------------------------------------------------------------
# OSV-Scanner
# ---------------------------------------------------------------------------


def _run_osv(target: Target) -> list[Finding]:
    if not _has_lockfile(target.root):
        return []
    cmd = [
        "osv-scanner",
        "scan", "source",
        "--format", "json",
        "--recursive",
        str(target.root),
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    # osv-scanner exits non-zero when vulnerabilities are present; that's
    # not an error condition for us — we still want to parse the report.
    if not proc.stdout.strip():
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    return parse_osv_json(data, root=target.root)


def parse_osv_json(data: dict[str, Any], root: Path | None = None) -> list[Finding]:
    """Parse osv-scanner JSON into Findings.

    Schema (osv-scanner v1.x): top-level `results` is a list, each entry
    has a `source` (path + lockfile type) and a `packages` list. Each
    package can have `vulnerabilities` (raw OSV records) and `groups`
    (deduplicated alias clusters with a max severity hint).
    """
    out: list[Finding] = []
    for result in data.get("results") or []:
        source_path = (result.get("source") or {}).get("path") or "?"
        rel_path = normalize_to_root(source_path, root)

        # Build a quick lookup from any alias/id -> max group severity, so
        # we don't re-emit dozens of duplicate aliases for the same advisory.
        group_severity: dict[str, str] = {}
        for pkg in result.get("packages") or []:
            for grp in pkg.get("groups") or []:
                max_sev = (grp.get("max_severity") or "").strip()
                for ident in grp.get("ids") or []:
                    if max_sev and ident not in group_severity:
                        group_severity[ident] = max_sev

        for pkg in result.get("packages") or []:
            pkg_info = pkg.get("package") or {}
            pkg_name = pkg_info.get("name") or "?"
            pkg_version = pkg_info.get("version") or "?"
            ecosystem = pkg_info.get("ecosystem") or "?"

            for vuln in pkg.get("vulnerabilities") or []:
                vid = vuln.get("id") or "OSV-UNKNOWN"
                aliases = vuln.get("aliases") or []
                # Prefer CVE alias for human readability, fall back to native id.
                primary = next((a for a in aliases if a.startswith("CVE-")), vid)

                summary = (vuln.get("summary") or vuln.get("details") or vid).strip()
                if len(summary) > 200:
                    summary = summary[:197] + "..."

                # Severity: try group's max_severity first (CVSS string),
                # then OSV record's database_specific.severity, then fall back
                # to "medium" because an unscored advisory is still real.
                sev_label = _osv_severity_for(vuln, group_severity)
                severity = _OSV_SEVERITY.get(sev_label.upper(), "medium")

                cwe_field = (
                    (vuln.get("database_specific") or {}).get("cwe_ids")
                    or vuln.get("cwe_ids")
                    or []
                )
                if not cwe_field:
                    # No CWE in advisory -> treat as generic supply-chain.
                    cwe = ("CWE-1104",)
                else:
                    cwe = tuple(c if c.startswith("CWE-") else f"CWE-{c}" for c in cwe_field)

                fixed = _osv_fixed_version(vuln, pkg_version)
                fix_hint = (
                    f"Bump {pkg_name} to {fixed}"
                    if fixed
                    else f"No fixed version published yet for {pkg_name}; "
                    f"consider an alternative or pin to a known-safe revision."
                )

                out.append(
                    Finding(
                        rule_id=primary,
                        severity=severity,
                        path=rel_path,
                        line=0,
                        message=(
                            f"{primary} in {pkg_name} {pkg_version} ({ecosystem}): {summary}"
                        ),
                        source="supply_chain:osv",
                        cwe=cwe,
                        snippet=None,
                        confidence=1.0,
                        fix_hint=fix_hint,
                        raw=vuln,
                    )
                )
    return out


def _osv_severity_for(vuln: dict[str, Any], group_severity: dict[str, str]) -> str:
    """Best-effort severity bucket from OSV's many possible severity fields."""
    vid = vuln.get("id", "")
    if vid in group_severity:
        return group_severity[vid]
    db = vuln.get("database_specific") or {}
    if db.get("severity"):
        return str(db["severity"])
    sev_list = vuln.get("severity") or []
    for s in sev_list:
        score = s.get("score")
        if not score:
            continue
        # Crude CVSS string parse: extract base score if present.
        try:
            for part in score.split("/"):
                if part.startswith(("CVSS:", "AV:")):
                    continue
                v = float(part.split(":")[-1])
                if v >= 9.0:
                    return "CRITICAL"
                if v >= 7.0:
                    return "HIGH"
                if v >= 4.0:
                    return "MEDIUM"
                return "LOW"
        except (ValueError, AttributeError):
            continue
    return "MEDIUM"


def _osv_fixed_version(vuln: dict[str, Any], current: str) -> str | None:
    """Pick the smallest 'fixed' version listed in the advisory's affected ranges."""
    fixes: list[str] = []
    for affected in vuln.get("affected") or []:
        for rng in affected.get("ranges") or []:
            for ev in rng.get("events") or []:
                if "fixed" in ev:
                    fixes.append(str(ev["fixed"]))
    fixes = sorted(set(fixes))
    if not fixes:
        return None
    # We don't try to pick "the smallest >= current" — semver compare is
    # ecosystem-specific and we don't want to lie. Just surface the lowest
    # fix version, which is the most actionable single answer.
    return fixes[0]


def _has_lockfile(root: Path) -> bool:
    if not root.is_dir():
        return False
    for lf in _OSV_LOCKFILES:
        if (root / lf).is_file():
            return True
    # Also accept lockfiles in immediate subdirectories (monorepos).
    for child in root.iterdir():
        if not child.is_dir():
            continue
        if any((child / lf).is_file() for lf in _OSV_LOCKFILES):
            return True
    return False


# ---------------------------------------------------------------------------
# OpenSSF Scorecard
# ---------------------------------------------------------------------------


def _run_scorecard(target: Target) -> list[Finding]:
    repo = _detect_github_repo(target.root)
    if not repo:
        return []
    env = os.environ.copy()
    if "GITHUB_AUTH_TOKEN" not in env and "GITHUB_TOKEN" in env:
        env["GITHUB_AUTH_TOKEN"] = env["GITHUB_TOKEN"]
    cmd = ["scorecard", f"--repo={repo}", "--format=json", "--show-details"]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
            env=env,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    return parse_scorecard_json(data, repo=repo)


def parse_scorecard_json(data: dict[str, Any], repo: str = "?") -> list[Finding]:
    """Surface checks scoring <= _SCORECARD_THRESHOLD as Findings.

    A high overall Scorecard rating is not actionable; the actionable
    signal is *which checks are failing* (e.g. "Branch-Protection: 0",
    "Signed-Releases: 0"). We emit one Finding per low-scoring check
    so they show up alongside other supply-chain risks in the report.
    """
    out: list[Finding] = []
    repo_label = (data.get("repo") or {}).get("name") or repo
    for check in data.get("checks") or []:
        name = str(check.get("name") or "Scorecard-Unknown")
        score = check.get("score")
        if score is None:
            continue
        try:
            score_i = int(score)
        except (TypeError, ValueError):
            continue
        if score_i < 0 or score_i > _SCORECARD_THRESHOLD:
            continue
        reason = (check.get("reason") or "").strip()
        severity: Severity = "high" if score_i == 0 else "medium"
        url = (check.get("documentation") or {}).get("url") or ""
        msg = f"OpenSSF Scorecard '{name}' = {score_i}/10 on {repo_label}: {reason}"
        if url:
            msg += f" ({url})"
        out.append(
            Finding(
                rule_id=f"scorecard-{name.lower()}",
                severity=severity,
                path="(repo)",
                line=0,
                message=msg,
                source="supply_chain:scorecard",
                cwe=("CWE-1357",),
                confidence=0.9,
                fix_hint=_scorecard_fix_hint(name),
                raw=check,
            )
        )
    return out


_SCORECARD_FIXES: dict[str, str] = {
    "branch-protection": (
        "Enable branch protection on default branch (require PR review, status checks)."
    ),
    "signed-releases": "Sign release artifacts with cosign or GPG.",
    "fuzzing": "Add OSS-Fuzz integration or run continuous fuzzing in CI.",
    "security-policy": "Add a SECURITY.md describing the disclosure process.",
    "dependency-update-tool": "Enable Dependabot or Renovate.",
    "pinned-dependencies": "Pin GitHub Actions and Docker images to commit SHAs.",
    "token-permissions": "Set top-level `permissions: read-all` and grant write only where needed.",
    "code-review": "Require at least one code review on every PR.",
    "maintained": "If unmaintained, fork and maintain internally or migrate.",
    "ci-tests": "Wire up CI tests on every PR.",
    "license": "Add a LICENSE file (OSI-approved).",
    "binary-artifacts": "Remove committed binary artifacts; build from source.",
}


def _scorecard_fix_hint(check_name: str) -> str:
    return _SCORECARD_FIXES.get(check_name.lower(), f"See OpenSSF Scorecard docs for '{check_name}'.")


def _detect_github_repo(root: Path) -> str | None:
    """Return 'github.com/<owner>/<name>' if `root` is a clone of a GH repo."""
    if not (root / ".git").exists():
        return None
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "config", "--get", "remote.origin.url"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0:
        return None
    url = proc.stdout.strip()
    if not url:
        return None
    # https://github.com/owner/repo(.git) or git@github.com:owner/repo(.git)
    if url.startswith("git@github.com:"):
        body = url.split(":", 1)[1]
    elif "github.com/" in url:
        body = url.split("github.com/", 1)[1]
    else:
        return None
    body = body.removesuffix(".git").strip("/")
    if body.count("/") < 1:
        return None
    return f"github.com/{body}"


# ---------------------------------------------------------------------------
# guarddog (PyPI malicious-package heuristics)
# ---------------------------------------------------------------------------


_GUARDDOG_RULE_PREFIXES = (
    "deceptive_", "exfiltrate_", "code_execution_",
    "obfuscation_", "typosquatting", "single_python_file",
)


def _run_guarddog(target: Target) -> list[Finding]:
    """Scan PyPI requirements with guarddog.

    We only run on declared *direct* dependencies (top of requirements.txt)
    to keep call cost bounded. guarddog hits PyPI, downloads each package,
    and runs heuristic rules — one call per package, so we cap at 50.
    """
    deps = _direct_pypi_deps(target.root)
    if not deps:
        return []
    out: list[Finding] = []
    for dep in deps[:50]:
        try:
            proc = subprocess.run(
                ["guarddog", "pypi", "scan", dep, "--output-format", "json"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError):
            continue
        if proc.returncode not in (0, 1) or not proc.stdout.strip():
            # guarddog exits 1 when it found something — that's a hit, not an error.
            continue
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            continue
        out.extend(parse_guarddog_json(data, dep))
    return out


def parse_guarddog_json(data: dict[str, Any], package: str) -> list[Finding]:
    """Parse guarddog's per-package JSON.

    guarddog emits roughly:
      {"results": {"<rule_name>": [<match_details>, ...] | str}, ...}
    Different versions structure this slightly differently; we handle both
    shapes defensively because being wrong here means missing a malicious
    package. False positives are easy to triage; false negatives are not.
    """
    out: list[Finding] = []
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, dict):
        return out
    for rule, hit in results.items():
        if not hit:
            continue
        # Skip generic / metadata-only rules; we want behavioral matches.
        # Backstop: any rule name containing 'malicious' is always behavioral.
        if (
            not any(rule.startswith(p) for p in _GUARDDOG_RULE_PREFIXES)
            and "malicious" not in rule.lower()
        ):
            continue
        snippet: str | None = None
        if isinstance(hit, list) and hit:
            first = hit[0]
            if isinstance(first, dict):
                snippet = (first.get("code") or first.get("file") or "")[:300] or None
            elif isinstance(first, str):
                snippet = first[:300]
        elif isinstance(hit, str):
            snippet = hit[:300]
        out.append(
            Finding(
                rule_id=f"guarddog-{rule}",
                severity="critical",
                path="(dependency)",
                line=0,
                message=(
                    f"guarddog flagged PyPI package {package!r} on rule {rule!r}: "
                    f"this looks like a *malicious* (not vulnerable) package."
                ),
                source="supply_chain:guarddog",
                cwe=("CWE-506",),
                snippet=snippet,
                confidence=0.85,
                fix_hint=(
                    f"Remove {package!r} from dependencies. If the name is a "
                    f"typosquat, find the legitimate package; otherwise audit "
                    f"the install scripts and any imports of {package!r}."
                ),
                raw={"package": package, "rule": rule, "hit": hit},
            )
        )
    return out


def _direct_pypi_deps(root: Path) -> list[str]:
    req = root / "requirements.txt"
    if not req.is_file():
        return []
    out: list[str] = []
    try:
        text = req.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-r", "--")):
            continue
        # Strip version specifiers / extras / env markers.
        for sep in ("=", ">", "<", "~", "!", ";", "[", " "):
            if sep in line:
                line = line.split(sep, 1)[0]
        line = line.strip()
        if line and line not in out:
            out.append(line)
    return out
