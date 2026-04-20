"""Rich-backed sink for ``s0_cli.harness.progress`` events.

Renders one of two views to stderr:

- *quiet* (default for ``s0 scan`` on a TTY): a single dynamic ``Status`` line
  showing what is happening right now (e.g. ``running scanner trivy (4/7)`` or
  ``agent turn 5/30 · 9.2k tokens · tool: read_file``).
- *verbose* (``-v``): every event is also logged on its own line above the
  spinner with a duration, so the user can see the full timeline.

The sink is fully optional — if Rich rendering is disabled (no TTY, ``-q``)
nothing is installed and the harness stays completely silent.
"""

from __future__ import annotations

import contextlib
from typing import Any

from rich.console import Console
from rich.status import Status


def _fmt_tokens(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}k"
    return str(n)


def _fmt_args(args: dict[str, Any]) -> str:
    if not args:
        return ""
    parts: list[str] = []
    for key in ("path", "name", "pattern", "rule_id", "command"):
        if key in args and args[key]:
            val = str(args[key])
            if len(val) > 48:
                val = val[:45] + "..."
            parts.append(f"{key}={val}")
            break
    if not parts:
        first = next(iter(args))
        val = str(args[first])
        if len(val) > 48:
            val = val[:45] + "..."
        parts.append(f"{first}={val}")
    return " " + " ".join(parts)


class RichProgressSink:
    """Stateful progress sink. Use as a context manager around a scan call."""

    def __init__(self, console: Console, *, verbose: bool = False) -> None:
        self.console = console
        self.verbose = verbose
        self._status: Status | None = None
        self._current_phase: str | None = None
        self._scanner_total = 0
        self._tokens_in = 0
        self._tokens_out = 0
        self._reasoning_tokens = 0
        self._max_turns = 0
        # Latches ON the first time we see a reasoning model name OR a turn
        # that returned actual reasoning content/tokens. Stays ON for the
        # rest of the scan so the spinner doesn't flicker.
        self._is_reasoning = False

    def __enter__(self) -> RichProgressSink:
        self._status = self.console.status(
            "[cyan]starting…[/cyan]", spinner="dots", spinner_style="cyan"
        )
        self._status.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._status is not None:
            self._status.__exit__(exc_type, exc, tb)
            self._status = None

    def __call__(self, event: str, fields: dict[str, Any]) -> None:
        with contextlib.suppress(Exception):
            self._handle(event, fields)

    def _set(self, msg: str) -> None:
        if self._status is not None:
            self._status.update(msg)

    def _log(self, msg: str) -> None:
        if self.verbose:
            self.console.log(msg)

    def _handle(self, event: str, f: dict[str, Any]) -> None:
        if event == "phase_start":
            name = f.get("name", "?")
            self._current_phase = name
            if name == "env_snapshot":
                self._set("[cyan]inspecting environment…[/cyan]")
                self._log("[dim]→[/dim] env_snapshot")
            elif name == "seed_scanners":
                scanners = f.get("scanners") or []
                self._scanner_total = len(scanners)
                self._set(
                    f"[cyan]running scanners[/cyan] (0/{self._scanner_total})"
                )
                self._log(
                    f"[dim]→[/dim] seed_scanners ({', '.join(scanners)})"
                )
            elif name == "agent_loop":
                self._max_turns = int(f.get("max_turns") or 0)
                self._set("[cyan]starting agent loop…[/cyan]")
                self._log(f"[dim]→[/dim] agent_loop (max_turns={self._max_turns})")
            return

        if event == "phase_done":
            name = f.get("name", "?")
            if name == "env_snapshot":
                self._log(f"[green]✓[/green] env_snapshot files={f.get('file_count', 0)}")
            elif name == "seed_scanners":
                count = f.get("findings", 0)
                self._log(f"[green]✓[/green] seed_scanners → {count} candidate(s)")
                self._set(f"[cyan]scanners done — {count} candidates[/cyan]")
            elif name == "agent_loop":
                turns = f.get("turns", 0)
                ended = f.get("ended_via", "?")
                self._log(
                    f"[green]✓[/green] agent_loop turns={turns} ended_via={ended}"
                )
            return

        if event == "scanner_start":
            name = f.get("name", "?")
            i = f.get("index", 0)
            n = f.get("total", 0)
            self._set(f"[cyan]scanner {name}[/cyan] ({i}/{n})")
            return

        if event == "scanner_done":
            name = f.get("name", "?")
            i = f.get("index", 0)
            n = f.get("total", 0)
            dur = f.get("duration_ms", 0)
            err = f.get("error")
            findings = f.get("findings", 0)
            if err:
                self._set(f"[yellow]scanner {name} failed[/yellow] ({i}/{n})")
                self._log(f"[red]✗[/red] {name} failed: {err}")
            else:
                self._set(
                    f"[green]✓[/green] {name} → {findings} ({i}/{n}, {dur}ms)"
                )
                self._log(
                    f"[green]✓[/green] {name} → {findings} finding(s) "
                    f"[dim]({dur}ms)[/dim]"
                )
            return

        if event == "scanner_skip":
            name = f.get("name", "?")
            reason = f.get("reason", "?")
            self._log(f"[yellow]·[/yellow] skip {name} ({reason})")
            return

        if event == "llm_turn_start":
            turn = f.get("turn", 0)
            self._tokens_in = int(f.get("tokens_in", 0) or 0)
            self._tokens_out = int(f.get("tokens_out", 0) or 0)
            if f.get("is_reasoning"):
                self._is_reasoning = True
            total = self._tokens_in + self._tokens_out
            if self._is_reasoning:
                # Magenta + brain emoji is the universal "reasoning" cue and
                # a clear signal that latency before the first token is
                # expected — not a hang.
                tail = "thinking…"
                colour = "magenta"
            else:
                tail = "waiting on LLM…"
                colour = "cyan"
            self._set(
                f"[{colour}]agent turn {turn}/{self._max_turns}[/{colour}] "
                f"· {_fmt_tokens(total)} tok · {tail}"
            )
            return

        if event == "llm_turn_done":
            turn = f.get("turn", 0)
            dur = f.get("duration_ms", 0)
            in_tok = int(f.get("input_tokens", 0) or 0)
            out_tok = int(f.get("output_tokens", 0) or 0)
            r_tok = int(f.get("reasoning_tokens", 0) or 0)
            if r_tok or f.get("is_reasoning"):
                self._is_reasoning = True
                self._reasoning_tokens += r_tok
            calls = f.get("tool_calls") or []
            calls_label = ", ".join(calls) if calls else f.get("finish_reason") or "—"
            r_part = f" reasoning={_fmt_tokens(r_tok)}" if r_tok else ""
            self._log(
                f"[blue]llm[/blue] turn {turn} "
                f"in={_fmt_tokens(in_tok)} out={_fmt_tokens(out_tok)}{r_part} "
                f"[dim]({dur}ms)[/dim] → {calls_label}"
            )
            return

        if event == "tool_call_start":
            turn = f.get("turn", 0)
            name = f.get("name", "?")
            args = f.get("arguments") or {}
            self._set(
                f"[cyan]agent turn {turn}/{self._max_turns}[/cyan] "
                f"· tool: [bold]{name}[/bold]{_fmt_args(args)}"
            )
            return

        if event == "tool_call_done":
            name = f.get("name", "?")
            dur = f.get("duration_ms", 0)
            self._log(f"[magenta]tool[/magenta] {name} [dim]({dur}ms)[/dim]")
            return
