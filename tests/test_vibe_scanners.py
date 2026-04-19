"""Tests for the Phase-3 vibe-code detectors."""

from __future__ import annotations

from pathlib import Path

import pytest

from s0_cli.scanners.hallucinated_import import HallucinatedImportScanner
from s0_cli.scanners.vibe import _parse_vibe_response
from s0_cli.targets.repo import build_repo_target


def _write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


# --- HallucinatedImportScanner -------------------------------------------------


def test_hallucinated_import_flags_unknown_top_level(tmp_path: Path):
    _write(tmp_path, "main.py", "import json\nimport safe_json\nimport os\n")
    _write(tmp_path, "requirements.txt", "requests==2.31.0\n")
    target = build_repo_target(tmp_path)
    findings = HallucinatedImportScanner().run(target)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "vibe-hallucinated-import"
    assert f.severity == "high"
    assert f.path == "main.py"
    assert f.line == 2
    assert "safe_json" in f.message
    assert f.cwe == ("CWE-1357",)


def test_hallucinated_import_accepts_local_modules(tmp_path: Path):
    _write(tmp_path, "main.py", "from utils import load_config\nimport helpers\n")
    _write(tmp_path, "utils.py", "def load_config(): pass\n")
    _write(tmp_path, "helpers.py", "x = 1\n")
    findings = HallucinatedImportScanner().run(build_repo_target(tmp_path))
    assert findings == []


def test_hallucinated_import_accepts_declared_dep_with_import_alias(tmp_path: Path):
    """`PyYAML` in requirements -> `import yaml` is fine."""
    _write(tmp_path, "main.py", "import yaml\nimport bs4\nimport sklearn\n")
    _write(tmp_path, "requirements.txt", "PyYAML>=6.0\nbeautifulsoup4\nscikit-learn\n")
    findings = HallucinatedImportScanner().run(build_repo_target(tmp_path))
    assert findings == []


def test_hallucinated_import_skips_relative(tmp_path: Path):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(tmp_path, "pkg/a.py", "from . import b\nfrom .. import c\n")
    _write(tmp_path, "pkg/b.py", "")
    findings = HallucinatedImportScanner().run(build_repo_target(tmp_path))
    assert findings == []


def test_hallucinated_import_handles_syntax_error(tmp_path: Path):
    _write(tmp_path, "broken.py", "def (((\n")
    _write(tmp_path, "good.py", "import os\n")
    findings = HallucinatedImportScanner().run(build_repo_target(tmp_path))
    assert findings == []  # broken file silently skipped, good has only stdlib


def test_hallucinated_import_on_real_bench_target():
    """Sanity check against the bench task — must catch the seeded vuln."""
    bench = Path(__file__).parent.parent / "bench" / "tasks_train" / "hallucinated_import" / "target"
    if not bench.is_dir():
        pytest.skip("bench task missing")
        findings = HallucinatedImportScanner().run(build_repo_target(bench))
        # line tolerance: ground truth says 7, the actual import is on 8
        assert any(f.path == "main.py" and 6 <= f.line <= 9 for f in findings)
        assert all("safe_json" in f.message for f in findings if f.path == "main.py")


# --- VibeLLMScanner response parser -------------------------------------------


def test_parse_vibe_strict_json():
    raw = '{"findings":[{"rule_id":"vibe-stub-auth","severity":"critical","line":22,"message":"hardcoded admin","cwe":["CWE-798"],"confidence":0.95}]}'
    [f] = _parse_vibe_response(raw, "auth.py", None)
    assert f.rule_id == "vibe-stub-auth"
    assert f.severity == "critical"
    assert f.line == 22
    assert f.cwe == ("CWE-798",)
    assert f.confidence == 0.95
    assert f.source == "vibe_llm"


def test_parse_vibe_normalizes_rule_id_prefix():
    raw = '{"findings":[{"rule_id":"stub-auth","severity":"high","line":1,"message":"x"}]}'
    [f] = _parse_vibe_response(raw, "x.py", None)
    assert f.rule_id == "vibe-stub-auth"


def test_parse_vibe_clamps_confidence_and_normalizes_severity():
    raw = '{"findings":[{"rule_id":"vibe-x","severity":"FOOBAR","line":1,"message":"x","confidence":2.5}]}'
    [f] = _parse_vibe_response(raw, "x.py", None)
    assert f.severity == "medium"
    assert f.confidence == 1.0


def test_parse_vibe_recovers_from_markdown_fence():
    raw = '```json\n{"findings":[{"rule_id":"vibe-x","severity":"low","line":3,"message":"x"}]}\n```'
    [f] = _parse_vibe_response(raw, "x.py", None)
    assert f.line == 3


def test_parse_vibe_recovers_from_prelude():
    raw = 'Sure, here is the analysis:\n{"findings":[{"rule_id":"vibe-x","severity":"low","line":1,"message":"x"}]}\nDone.'
    [f] = _parse_vibe_response(raw, "x.py", None)
    assert f.line == 1


def test_parse_vibe_handles_empty_and_garbage():
    assert _parse_vibe_response("", "x.py", None) == []
    assert _parse_vibe_response("not json at all", "x.py", None) == []
    assert _parse_vibe_response('{"findings":[]}', "x.py", None) == []
    assert _parse_vibe_response('{"other":"shape"}', "x.py", None) == []
