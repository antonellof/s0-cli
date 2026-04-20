"""Provider-key forwarding from `.env` and have_provider_key dispatch.

Covers the keys litellm reads directly from ``os.environ`` (and that
``pydantic-settings`` does not because they lack the ``S0_`` prefix). New
providers added to ``_PROVIDER_KEYS`` should grow the parametrized cases below.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from s0_cli.config import _load_dotenv_provider_keys
from s0_cli.harness.llm import have_provider_key


@pytest.fixture
def clean_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Iterator[None]:
    """Hermetic env: strip provider keys + redirect HOME + CWD to tmp.

    The loader walks several standard locations (``./.env``,
    ``~/.config/s0/.env``, ``~/.s0/.env``). To keep tests reproducible
    across dev machines and CI, we point HOME at an empty tmp dir and
    chdir into another empty tmp dir so only files the test creates
    explicitly are visible.
    """
    for key in (
        "OPENAI_API_KEY",
        "OPENAI_API_BASE",
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "GROQ_API_KEY",
        "MISTRAL_API_KEY",
        "DEEPSEEK_API_KEY",
        "OPENROUTER_API_KEY",
        "OPENROUTER_API_BASE",
        "OLLAMA_API_BASE",
        "OLLAMA_API_KEY",
        "AZURE_API_KEY",
        "AZURE_API_BASE",
        "AZURE_API_VERSION",
        "S0_ENV_FILE",
    ):
        monkeypatch.delenv(key, raising=False)
    home = tmp_path / "home"
    cwd = tmp_path / "cwd"
    home.mkdir()
    cwd.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(cwd)
    yield


def test_dotenv_loader_forwards_openrouter_keys(
    tmp_path: Path, clean_env: None
) -> None:
    env = tmp_path / ".env"
    env.write_text(
        "OPENROUTER_API_KEY=sk-or-test\n"
        "OPENROUTER_API_BASE=https://my-proxy.example/api/v1\n",
        encoding="utf-8",
    )
    _load_dotenv_provider_keys(env)
    assert os.environ["OPENROUTER_API_KEY"] == "sk-or-test"
    assert os.environ["OPENROUTER_API_BASE"] == "https://my-proxy.example/api/v1"


def test_dotenv_loader_forwards_ollama_keys(
    tmp_path: Path, clean_env: None
) -> None:
    env = tmp_path / ".env"
    env.write_text(
        "OLLAMA_API_BASE=https://ollama.mycorp.com\n"
        "OLLAMA_API_KEY=bearer-xyz\n",
        encoding="utf-8",
    )
    _load_dotenv_provider_keys(env)
    assert os.environ["OLLAMA_API_BASE"] == "https://ollama.mycorp.com"
    assert os.environ["OLLAMA_API_KEY"] == "bearer-xyz"


def test_dotenv_loader_forwards_openai_api_base(
    tmp_path: Path, clean_env: None
) -> None:
    """Self-hosted OpenAI-compatible servers (vLLM, llama.cpp, LM Studio)."""
    env = tmp_path / ".env"
    env.write_text(
        "OPENAI_API_BASE=http://localhost:8000/v1\n", encoding="utf-8"
    )
    _load_dotenv_provider_keys(env)
    assert os.environ["OPENAI_API_BASE"] == "http://localhost:8000/v1"


def test_dotenv_loader_does_not_overwrite_already_set_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the user already exported the key in their shell, .env loses."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "from-shell")
    env = tmp_path / ".env"
    env.write_text("OPENROUTER_API_KEY=from-dotenv\n", encoding="utf-8")
    _load_dotenv_provider_keys(env)
    assert os.environ["OPENROUTER_API_KEY"] == "from-shell"


def test_dotenv_loader_skips_unknown_keys(
    tmp_path: Path, clean_env: None
) -> None:
    """Random non-provider env keys must NOT leak into os.environ via this loader."""
    env = tmp_path / ".env"
    env.write_text("SOME_RANDOM_VAR=should-not-be-imported\n", encoding="utf-8")
    _load_dotenv_provider_keys(env)
    assert "SOME_RANDOM_VAR" not in os.environ


def test_dotenv_loader_finds_xdg_config_path(clean_env: None) -> None:
    """Standalone-binary case: no ./.env, key lives in ~/.config/s0/.env."""
    home = Path(os.environ["HOME"])
    cfg = home / ".config" / "s0"
    cfg.mkdir(parents=True)
    (cfg / ".env").write_text(
        "OPENAI_API_KEY=sk-from-xdg\n", encoding="utf-8"
    )
    loaded = _load_dotenv_provider_keys()
    assert os.environ["OPENAI_API_KEY"] == "sk-from-xdg"
    assert any(p.name == ".env" and ".config/s0" in str(p) for p in loaded)


def test_dotenv_loader_finds_dot_s0_path(clean_env: None) -> None:
    """Alternate location ~/.s0/.env should also be picked up."""
    home = Path(os.environ["HOME"])
    cfg = home / ".s0"
    cfg.mkdir()
    (cfg / ".env").write_text(
        "ANTHROPIC_API_KEY=sk-from-dot-s0\n", encoding="utf-8"
    )
    _load_dotenv_provider_keys()
    assert os.environ["ANTHROPIC_API_KEY"] == "sk-from-dot-s0"


def test_dotenv_loader_cwd_overrides_home(
    clean_env: None, tmp_path: Path
) -> None:
    """./.env (project-local) wins over ~/.config/s0/.env (machine-wide)."""
    home = Path(os.environ["HOME"])
    (home / ".config" / "s0").mkdir(parents=True)
    (home / ".config" / "s0" / ".env").write_text(
        "OPENAI_API_KEY=from-home\n", encoding="utf-8"
    )
    Path(".env").write_text("OPENAI_API_KEY=from-cwd\n", encoding="utf-8")
    _load_dotenv_provider_keys()
    assert os.environ["OPENAI_API_KEY"] == "from-cwd"


def test_dotenv_loader_explicit_path_wins(
    clean_env: None, tmp_path: Path
) -> None:
    """An explicit path (e.g. --env-file) beats every default location."""
    home = Path(os.environ["HOME"])
    (home / ".config" / "s0").mkdir(parents=True)
    (home / ".config" / "s0" / ".env").write_text(
        "OPENAI_API_KEY=from-home\n", encoding="utf-8"
    )
    Path(".env").write_text("OPENAI_API_KEY=from-cwd\n", encoding="utf-8")
    explicit = tmp_path / "custom.env"
    explicit.write_text("OPENAI_API_KEY=from-explicit\n", encoding="utf-8")
    _load_dotenv_provider_keys(explicit)
    assert os.environ["OPENAI_API_KEY"] == "from-explicit"


def test_s0_env_file_environment_variable(
    clean_env: None, tmp_path: Path
) -> None:
    """`S0_ENV_FILE=/path/to/file` is honored even without --env-file."""
    custom = tmp_path / "elsewhere.env"
    custom.write_text("GROQ_API_KEY=sk-from-s0-env-file\n", encoding="utf-8")
    os.environ["S0_ENV_FILE"] = str(custom)
    _load_dotenv_provider_keys()
    assert os.environ["GROQ_API_KEY"] == "sk-from-s0-env-file"


@pytest.mark.parametrize(
    ("model", "env", "expected"),
    [
        # --- hosted providers, key required ---
        ("anthropic/claude-sonnet-4-5", {"ANTHROPIC_API_KEY": "k"}, True),
        ("anthropic/claude-sonnet-4-5", {}, False),
        ("openai/gpt-4o-mini", {"OPENAI_API_KEY": "k"}, True),
        ("openai/gpt-4o-mini", {}, False),
        ("gemini/gemini-1.5-flash", {"GEMINI_API_KEY": "k"}, True),
        ("gemini/gemini-1.5-flash", {"GOOGLE_API_KEY": "k"}, True),
        ("gemini/gemini-1.5-flash", {}, False),
        # --- openrouter ---
        ("openrouter/anthropic/claude-3.5-sonnet", {"OPENROUTER_API_KEY": "k"}, True),
        ("openrouter/anthropic/claude-3.5-sonnet", {}, False),
        # --- ollama: local needs no key, the doctor must not false-flag it ---
        ("ollama/llama3.1", {}, True),
        ("ollama_chat/qwen2.5-coder", {}, True),
        ("ollama/llama3.1", {"OLLAMA_API_BASE": "https://…"}, True),
        # --- self-hosted OpenAI-compatible: OPENAI_API_BASE alone is enough ---
        ("openai/local-model", {"OPENAI_API_BASE": "http://localhost:8000/v1"}, True),
        # --- groq / mistral / deepseek / azure ---
        ("groq/llama-3.1-70b", {"GROQ_API_KEY": "k"}, True),
        ("groq/llama-3.1-70b", {}, False),
        ("mistral/mistral-large", {"MISTRAL_API_KEY": "k"}, True),
        ("mistral/mistral-large", {}, False),
        ("deepseek/deepseek-coder", {"DEEPSEEK_API_KEY": "k"}, True),
        ("deepseek/deepseek-coder", {}, False),
        (
            "azure/my-deployment",
            {
                "AZURE_API_KEY": "k",
                "AZURE_API_BASE": "https://r.openai.azure.com",
            },
            True,
        ),
        ("azure/my-deployment", {"AZURE_API_KEY": "k"}, False),
    ],
)
def test_have_provider_key_dispatch(
    model: str,
    env: dict[str, str],
    expected: bool,
    clean_env: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    assert have_provider_key(model) is expected
