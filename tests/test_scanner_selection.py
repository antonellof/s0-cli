"""``--scanner`` / ``--exclude-scanner`` resolution + ``s0 scanners`` listing."""

from __future__ import annotations

import pytest
import typer
from typer.testing import CliRunner

from s0_cli.cli import _resolve_scanner_selection, app


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# --- _resolve_scanner_selection unit tests -----------------------------------


def test_no_overrides_returns_harness_default() -> None:
    assert _resolve_scanner_selection(
        harness_default=("semgrep", "bandit"),
        include=None,
        exclude=None,
    ) == ("semgrep", "bandit")


def test_include_overrides_default_completely() -> None:
    """--scanner is a hard override, not an addition to the default set."""
    assert _resolve_scanner_selection(
        harness_default=("semgrep", "bandit", "ruff", "gitleaks", "trivy"),
        include=["bandit"],
        exclude=None,
    ) == ("bandit",)


def test_include_preserves_order_and_dedupes() -> None:
    assert _resolve_scanner_selection(
        harness_default=(),
        include=["trivy", "semgrep", "trivy", "bandit"],
        exclude=None,
    ) == ("trivy", "semgrep", "bandit")


def test_exclude_drops_listed_scanners_from_default() -> None:
    assert _resolve_scanner_selection(
        harness_default=("semgrep", "bandit", "ruff", "gitleaks", "trivy"),
        include=None,
        exclude=["trivy", "gitleaks"],
    ) == ("semgrep", "bandit", "ruff")


def test_exclude_against_empty_default_returns_empty() -> None:
    assert (
        _resolve_scanner_selection(
            harness_default=(),
            include=None,
            exclude=["semgrep"],
        )
        == ()
    )


def test_combining_include_and_exclude_is_an_error() -> None:
    with pytest.raises(typer.BadParameter, match="not both"):
        _resolve_scanner_selection(
            harness_default=("semgrep",),
            include=["bandit"],
            exclude=["trivy"],
        )


def test_unknown_include_scanner_lists_valid_ones() -> None:
    with pytest.raises(typer.BadParameter, match="Unknown scanner"):
        _resolve_scanner_selection(
            harness_default=(),
            include=["nopey-mcnopeface"],
            exclude=None,
        )


def test_unknown_exclude_scanner_lists_valid_ones() -> None:
    with pytest.raises(typer.BadParameter, match="Unknown scanner"):
        _resolve_scanner_selection(
            harness_default=("semgrep",),
            include=None,
            exclude=["nopey-mcnopeface"],
        )


# --- s0 scanners CLI command -------------------------------------------------


def test_scanners_command_lists_every_registered_scanner(runner: CliRunner) -> None:
    res = runner.invoke(app, ["scanners"])
    assert res.exit_code == 0, res.output
    for name in (
        "semgrep",
        "bandit",
        "ruff",
        "gitleaks",
        "trivy",
        "hallucinated_import",
        "vibe_llm",
    ):
        assert name in res.output


def test_scanners_command_shows_usage_hint(runner: CliRunner) -> None:
    res = runner.invoke(app, ["scanners"])
    assert "--scanner" in res.output
    assert "--exclude-scanner" in res.output


# --- s0 scan flag wiring -----------------------------------------------------


def test_scan_rejects_unknown_scanner_with_helpful_message(
    runner: CliRunner, tmp_path
) -> None:
    target = tmp_path / "x.py"
    target.write_text("print('hi')\n", encoding="utf-8")
    res = runner.invoke(
        app,
        [
            "scan",
            str(target),
            "--mode",
            "file",
            "--scanner",
            "made-up-tool",
            "--no-llm",
            "--quiet",
        ],
    )
    assert res.exit_code != 0
    assert "Unknown scanner" in res.output


def test_scan_rejects_combining_include_and_exclude(
    runner: CliRunner, tmp_path
) -> None:
    target = tmp_path / "x.py"
    target.write_text("print('hi')\n", encoding="utf-8")
    res = runner.invoke(
        app,
        [
            "scan",
            str(target),
            "--mode",
            "file",
            "--scanner",
            "semgrep",
            "--exclude-scanner",
            "trivy",
            "--no-llm",
            "--quiet",
        ],
    )
    assert res.exit_code != 0
    assert "not both" in res.output
