"""Reasoning-model detection + spinner mode in the progress sink.

Two layers of detection are tested:

1. Name-based heuristic (``is_reasoning_model``) — catches OpenAI o-series,
   GPT-5, Anthropic extended thinking, DeepSeek R1, Gemini thinking, QwQ.

2. Runtime sticky-flag in ``RichProgressSink`` — flips into "thinking…" mode
   the first time it sees ``is_reasoning=True`` on an event OR an
   ``llm_turn_done`` event reporting ``reasoning_tokens > 0``, and stays
   there for the rest of the scan.
"""

from __future__ import annotations

import io

import pytest
from rich.console import Console

from s0_cli.harness.llm import is_reasoning_model
from s0_cli.ui.progress import RichProgressSink, _fmt_bytes


@pytest.mark.parametrize(
    "model",
    [
        "openai/o1-mini",
        "openai/o3-mini",
        "openai/o4-mini",
        "openai/gpt-5",
        "openai/gpt-5-codex",
        "anthropic/claude-4.5-sonnet-thinking",
        "openrouter/anthropic/claude-sonnet-4-thinking",
        "deepseek/deepseek-r1",
        "deepseek/deepseek-reasoner",
        "ollama/deepseek-r1:7b",
        "gemini/gemini-2.5-pro",
        "gemini/gemini-2.0-flash-thinking-exp",
        "ollama/qwq:32b",
        "openrouter/qwen/qwq-32b-preview",
    ],
)
def test_reasoning_model_detected(model: str) -> None:
    assert is_reasoning_model(model) is True


@pytest.mark.parametrize(
    "model",
    [
        "openai/gpt-4o-mini",
        "openai/gpt-4.1",
        "anthropic/claude-sonnet-4-5",
        "anthropic/claude-3-5-sonnet",
        "openrouter/anthropic/claude-sonnet-4.6",
        "gemini/gemini-1.5-flash",
        "ollama/llama3.2",
        "ollama_chat/qwen2.5-coder",
        "groq/llama-3.1-70b",
        "",
    ],
)
def test_non_reasoning_model_not_detected(model: str) -> None:
    assert is_reasoning_model(model) is False


def _make_sink() -> tuple[RichProgressSink, io.StringIO]:
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=True, width=120, color_system=None)
    sink = RichProgressSink(console, verbose=True)
    return sink, buf


def test_sink_shows_thinking_when_event_says_reasoning() -> None:
    """Reasoning model name comes through as ``is_reasoning=True`` on events."""
    sink, _ = _make_sink()
    with sink:
        sink("phase_start", {"name": "agent_loop", "max_turns": 30})
        sink(
            "llm_turn_start",
            {"turn": 1, "max_turns": 30, "is_reasoning": True},
        )
    assert sink._is_reasoning is True


def test_sink_stays_in_normal_mode_for_non_reasoning_model() -> None:
    sink, _ = _make_sink()
    with sink:
        sink("phase_start", {"name": "agent_loop", "max_turns": 30})
        sink(
            "llm_turn_start",
            {"turn": 1, "max_turns": 30, "is_reasoning": False},
        )
    assert sink._is_reasoning is False


def test_sink_latches_thinking_after_reasoning_tokens_observed() -> None:
    """Self-correction: even if the name heuristic missed, the sink flips
    once a turn returns reasoning_tokens > 0 — and never flips back."""
    sink, _ = _make_sink()
    with sink:
        sink("phase_start", {"name": "agent_loop", "max_turns": 30})

        sink(
            "llm_turn_start",
            {"turn": 1, "max_turns": 30, "is_reasoning": False},
        )
        assert sink._is_reasoning is False

        sink(
            "llm_turn_done",
            {
                "turn": 1,
                "duration_ms": 12000,
                "input_tokens": 1000,
                "output_tokens": 50,
                "reasoning_tokens": 800,
                "tool_calls": [],
                "finish_reason": "stop",
                "is_reasoning": False,
            },
        )

        assert sink._is_reasoning is True
        assert sink._reasoning_tokens == 800

        sink(
            "llm_turn_start",
            {"turn": 2, "max_turns": 30, "is_reasoning": False},
        )
        assert sink._is_reasoning is True


def test_sink_handles_persist_and_render_phases() -> None:
    """Regression for the user-reported "stuck after agent_loop" symptom.

    Before this commit there was no progress signalling between agent_loop
    completion and the final ``console.print(markdown_text)`` call, which
    on a huge ThinkMoon-style scan (41,734 findings → 16 MB of markdown)
    silently wedged in Rich's renderer. The persist + render phase events
    + the 1 MB output cap in ``cmd_scan`` together fix the symptom.
    """
    sink, _ = _make_sink()
    with sink:
        # Should not raise on either new phase.
        sink("phase_start", {"name": "persist", "findings": 41734})
        sink("phase_done", {"name": "persist", "findings_bytes": 59 * 1024 * 1024})
        sink("phase_start", {"name": "render", "format": "markdown", "findings": 41734})
        sink("phase_done", {"name": "render", "bytes": 16_094_059})


@pytest.mark.parametrize(
    ("n", "expected"),
    [
        (0, "0B"),
        (512, "512B"),
        (1024, "1.0KB"),
        (1536, "1.5KB"),
        (1024 * 1024, "1.0MB"),
        (16_094_059, "15.3MB"),
    ],
)
def test_fmt_bytes(n: int, expected: str) -> None:
    assert _fmt_bytes(n) == expected


def test_sink_accumulates_reasoning_tokens_across_turns() -> None:
    sink, _ = _make_sink()
    with sink:
        for turn, r_tok in enumerate([400, 250, 0, 600], start=1):
            sink(
                "llm_turn_done",
                {
                    "turn": turn,
                    "duration_ms": 1000,
                    "input_tokens": 100,
                    "output_tokens": 20,
                    "reasoning_tokens": r_tok,
                    "tool_calls": [],
                    "finish_reason": "stop",
                },
            )
    assert sink._reasoning_tokens == 1250
