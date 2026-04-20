"""Sanity checks for the vulnhunter_v0 LLM-driven novelty harness.

We don't run the real LLM here (that's covered by the smoke + bench
tests). These tests pin the *contract* the harness must keep so that
downstream tooling (the scorer, the run-store, the proposer) keeps
working when the proposer rewrites this file.
"""

from __future__ import annotations

from s0_cli.harness.base import Harness, ScanResult
from s0_cli.harnesses.vulnhunter_v0 import VulnhunterV0, _normalize_source
from s0_cli.scanners.base import Finding


def test_vulnhunter_subclasses_harness() -> None:
    h = VulnhunterV0()
    assert isinstance(h, Harness)
    assert h.name == "vulnhunter_v0"


def test_vulnhunter_does_not_seed_from_classic_scanners() -> None:
    """This harness deliberately starts with no scanner seeds — the whole
    point is to find what classic scanners cannot. If a future proposer
    edit reverts this, we want CI to scream."""
    assert VulnhunterV0.default_scanners == ()


def test_vulnhunter_has_bounded_token_and_turn_budget() -> None:
    h = VulnhunterV0()
    assert 1 <= h.max_turns <= 100  # somebody removing the cap = bug
    assert 1_000 <= h.token_budget <= 1_000_000
    assert h.output_cap_bytes > 0


def test_vulnhunter_with_no_llm_disables_llm() -> None:
    h = VulnhunterV0()
    h.with_no_llm()
    assert h._llm.no_llm is True


def test_vulnhunter_loads_via_eval_runner_machinery() -> None:
    """The eval runner uses importlib + Harness-subclass discovery to
    load harnesses by name. Make sure that path actually finds us."""
    from s0_cli.eval.runner import load_harness_by_name

    h = load_harness_by_name("vulnhunter_v0")
    assert isinstance(h, VulnhunterV0)


def test_normalize_source_tags_existing_unprefixed_finding() -> None:
    raw = Finding(
        rule_id="ssrf-webhook",
        severity="high",
        path="app.py",
        line=42,
        message="x",
        source="llm",
    )
    out = _normalize_source(raw)
    assert out.source == "vulnhunter:llm"
    assert out.rule_id == "vulnhunter-ssrf-webhook"


def test_normalize_source_is_idempotent() -> None:
    raw = Finding(
        rule_id="vulnhunter-ssrf",
        severity="high",
        path="app.py",
        line=1,
        message="x",
        source="vulnhunter",
    )
    assert _normalize_source(raw) is raw  # unchanged objects must be identity-equal


def test_normalize_source_handles_empty_source() -> None:
    raw = Finding(
        rule_id="vulnhunter-x",
        severity="low",
        path="a.py",
        line=1,
        message="x",
        source="",
    )
    assert _normalize_source(raw).source == "vulnhunter"


def test_prompt_template_renders_with_required_keys() -> None:
    """The harness will crash on the first scan if the prompt template
    expects a placeholder we forgot to pass. Catch that statically."""
    from s0_cli.prompts import load as load_prompt

    text = load_prompt("vulnhunter_v0.txt")
    rendered = text.format(env="ENV", tools_summary="TOOLS", max_turns=10)
    assert "ENV" in rendered
    assert "TOOLS" in rendered
    assert "10" in rendered


def test_prompt_includes_eight_target_classes() -> None:
    """Pin the contract that the prompt enumerates the eight CWE classes
    the harness is documented to hunt for. If a proposer trims this list,
    we want to know."""
    from s0_cli.prompts import load as load_prompt

    text = load_prompt("vulnhunter_v0.txt").lower()
    # One representative keyword per target class.
    for needle in (
        "ssrf",
        "deserialization",
        "idor",
        "session bypass",
        "race condition",
        "mass assignment",
        "iv/nonce",
        "path traversal",
    ):
        assert needle in text, f"prompt missing target-class anchor: {needle!r}"


def test_scan_result_shape_is_compatible_with_run_store() -> None:
    """Smoke contract: a freshly-instantiated harness can produce a
    valid empty ScanResult. (We mock no LLM here; we just validate
    that the dataclass shape the runner expects is intact.)"""
    r = ScanResult()
    assert r.findings == []
    assert isinstance(r.usage, dict)
    assert isinstance(r.trace, list)
