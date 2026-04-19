"""ContextVar-backed progress sink behavior."""

from __future__ import annotations

from s0_cli.harness.progress import emit, reset_sink, set_sink


def test_emit_no_sink_is_noop() -> None:
    emit("anything", foo=1)


def test_emit_routes_event_and_fields_to_sink() -> None:
    seen: list[tuple[str, dict]] = []

    def cb(event, fields):
        seen.append((event, fields))

    token = set_sink(cb)
    try:
        emit("scanner_start", name="semgrep", index=1, total=5)
        emit("scanner_done", name="semgrep", findings=3)
    finally:
        reset_sink(token)

    assert seen == [
        ("scanner_start", {"name": "semgrep", "index": 1, "total": 5}),
        ("scanner_done", {"name": "semgrep", "findings": 3}),
    ]


def test_sink_failure_is_swallowed() -> None:
    def boom(event, fields):
        raise RuntimeError("ui crashed")

    token = set_sink(boom)
    try:
        emit("hello")
    finally:
        reset_sink(token)


def test_reset_sink_restores_silence() -> None:
    seen: list[tuple[str, dict]] = []
    token = set_sink(lambda e, f: seen.append((e, f)))
    emit("a")
    reset_sink(token)
    emit("b")
    assert seen == [("a", {})]


def test_rich_progress_sink_handles_phase_and_scanner_events() -> None:
    from rich.console import Console

    from s0_cli.ui.progress import RichProgressSink

    console = Console(force_terminal=False, record=True, width=120)
    with RichProgressSink(console, verbose=True) as sink:
        sink("phase_start", {"name": "seed_scanners", "scanners": ["semgrep", "bandit"]})
        sink("scanner_start", {"name": "semgrep", "index": 1, "total": 2})
        sink(
            "scanner_done",
            {"name": "semgrep", "index": 1, "total": 2, "findings": 4, "duration_ms": 120},
        )
        sink(
            "scanner_done",
            {
                "name": "bandit",
                "index": 2,
                "total": 2,
                "error": "RuntimeError: nope",
                "duration_ms": 5,
            },
        )
        sink("phase_done", {"name": "seed_scanners", "findings": 4})
        sink("llm_turn_start", {"turn": 1, "tokens_in": 0, "tokens_out": 0})
        sink(
            "llm_turn_done",
            {
                "turn": 1,
                "duration_ms": 800,
                "input_tokens": 1234,
                "output_tokens": 56,
                "tool_calls": ["read_file"],
            },
        )
        sink(
            "tool_call_start",
            {"turn": 1, "name": "read_file", "arguments": {"path": "app.py"}},
        )
        sink("tool_call_done", {"turn": 1, "name": "read_file", "duration_ms": 12})

    output = console.export_text()
    assert "semgrep" in output
    assert "bandit" in output
    assert "read_file" in output
