"""`s0 init` — non-interactive wizard behavior."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from s0_cli.cli import app


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def test_non_interactive_writes_minimal_openai_env(
    runner: CliRunner, tmp_path: Path
) -> None:
    out = tmp_path / ".env"
    result = runner.invoke(
        app,
        [
            "init",
            "--non-interactive",
            "--provider",
            "openai",
            "--api-key",
            "sk-test-1234",
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    text = out.read_text(encoding="utf-8")
    assert "S0_MODEL=openai/gpt-4o-mini" in text
    assert "OPENAI_API_KEY=sk-test-1234" in text
    # Other providers' keys should not be emitted to keep the file clean.
    assert "ANTHROPIC_API_KEY" not in text
    assert "OLLAMA_API_BASE" not in text


def test_non_interactive_ollama_emits_base_url_and_no_key(
    runner: CliRunner, tmp_path: Path
) -> None:
    out = tmp_path / "ollama.env"
    result = runner.invoke(
        app,
        [
            "init",
            "--non-interactive",
            "--provider",
            "ollama",
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    text = out.read_text(encoding="utf-8")
    assert "S0_MODEL=ollama/llama3.1" in text
    assert "OLLAMA_API_BASE=http://localhost:11434" in text
    # No API key block at all for the local Ollama default.
    assert "OPENAI_API_KEY" not in text
    assert "ANTHROPIC_API_KEY" not in text


def test_non_interactive_requires_api_key_for_hosted_providers(
    runner: CliRunner, tmp_path: Path
) -> None:
    out = tmp_path / "needs-key.env"
    result = runner.invoke(
        app,
        [
            "init",
            "--non-interactive",
            "--provider",
            "anthropic",
            "--out",
            str(out),
        ],
    )
    assert result.exit_code != 0
    assert "api-key" in result.output.lower() or "S0_INIT_API_KEY" in result.output
    assert not out.exists()


def test_non_interactive_picks_up_api_key_from_env(
    runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "env-key.env"
    monkeypatch.setenv("S0_INIT_API_KEY", "sk-from-env")
    result = runner.invoke(
        app,
        [
            "init",
            "--non-interactive",
            "--provider",
            "anthropic",
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "ANTHROPIC_API_KEY=sk-from-env" in out.read_text(encoding="utf-8")


def test_refuses_to_overwrite_existing_file(
    runner: CliRunner, tmp_path: Path
) -> None:
    out = tmp_path / "exists.env"
    out.write_text("# pre-existing\n", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "init",
            "--non-interactive",
            "--provider",
            "openai",
            "--api-key",
            "sk-x",
            "--out",
            str(out),
        ],
    )
    assert result.exit_code != 0
    assert "already exists" in result.output
    # Original content untouched.
    assert out.read_text(encoding="utf-8") == "# pre-existing\n"


def test_force_overwrites_existing_file(runner: CliRunner, tmp_path: Path) -> None:
    out = tmp_path / "force.env"
    out.write_text("# old\n", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "init",
            "--non-interactive",
            "--provider",
            "openai",
            "--api-key",
            "sk-new",
            "--out",
            str(out),
            "--force",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "OPENAI_API_KEY=sk-new" in out.read_text(encoding="utf-8")


def test_writes_with_owner_only_perms(runner: CliRunner, tmp_path: Path) -> None:
    out = tmp_path / "perms.env"
    result = runner.invoke(
        app,
        [
            "init",
            "--non-interactive",
            "--provider",
            "openai",
            "--api-key",
            "sk-secret",
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    mode = stat.S_IMODE(out.stat().st_mode)
    # 0o600 — readable + writable by owner only. We don't enforce on
    # platforms (e.g. Windows / restricted FS) where chmod is a no-op,
    # but on POSIX we want this strictly locked down.
    assert mode == 0o600, oct(mode)


def test_unknown_provider_is_rejected(runner: CliRunner, tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "init",
            "--non-interactive",
            "--provider",
            "definitely-not-a-provider",
            "--api-key",
            "sk-x",
            "--out",
            str(tmp_path / "x.env"),
        ],
    )
    assert result.exit_code != 0
    assert "definitely-not-a-provider" in result.output


def test_custom_model_overrides_provider_default(
    runner: CliRunner, tmp_path: Path
) -> None:
    out = tmp_path / "custom-model.env"
    result = runner.invoke(
        app,
        [
            "init",
            "--non-interactive",
            "--provider",
            "anthropic",
            "--api-key",
            "sk-ant-x",
            "--model",
            "anthropic/claude-3-5-haiku-latest",
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    text = out.read_text(encoding="utf-8")
    assert "S0_MODEL=anthropic/claude-3-5-haiku-latest" in text
    assert "anthropic/claude-sonnet-4-5" not in text
