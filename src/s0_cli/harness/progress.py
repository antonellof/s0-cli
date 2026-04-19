"""Optional in-process progress reporting via a ContextVar sink.

Harnesses, scanners, and the agent loop call ``emit("event_name", **fields)``
at interesting milestones (scanner started, llm turn finished, tool call
dispatched, etc.). If no sink is installed in the current context the call is
a cheap no-op, so this module is always safe to import and call.

The CLI installs a Rich-backed sink for ``s0 scan`` so the user sees what is
happening; tests and the eval/optimizer runners install nothing and stay quiet.

Design notes:
- Uses ``contextvars`` so we don't have to thread a ``progress=`` argument
  through every harness/loop/scanner signature (and so proposer-generated
  harnesses still work without modification).
- Sinks must never raise; failures are swallowed so a UI bug can't kill a scan.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from contextvars import ContextVar, Token
from typing import Any

ProgressCallback = Callable[[str, dict[str, Any]], None]

_sink: ContextVar[ProgressCallback | None] = ContextVar(
    "s0_progress_sink", default=None
)


def set_sink(cb: ProgressCallback | None) -> Token:
    """Install ``cb`` as the active sink. Returns a token for ``reset_sink``."""
    return _sink.set(cb)


def reset_sink(token: Token) -> None:
    _sink.reset(token)


def emit(event: str, **fields: Any) -> None:
    """Send a progress event to the active sink, if any. Never raises."""
    cb = _sink.get()
    if cb is None:
        return
    with contextlib.suppress(Exception):
        cb(event, fields)
