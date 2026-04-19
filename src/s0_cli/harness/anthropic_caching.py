"""Anthropic ephemeral prompt caching.

Ported pattern from KRAFTON AI's KIRA `anthropic_caching.py`. Adds
`cache_control: {type: "ephemeral"}` markers to the system prompt and the
last few user/tool messages so the Anthropic API caches the long stable
prefix between turns.

litellm forwards the markers through transparently for Anthropic models;
for other providers they're a no-op (litellm strips unknown fields).

Anthropic allows up to 4 cache breakpoints. We use them on:
  1. The system prompt (stable across the whole loop).
  2. The first user message (stable across the loop).
  3. The most recent tool/observation message (changes each turn but
     caches the prefix up to it).
  4. (reserved)
"""

from __future__ import annotations

from typing import Any

CACHE_CONTROL: dict[str, str] = {"type": "ephemeral"}


def add_anthropic_caching(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return a shallow-copied list with cache_control markers inserted.

    Mutates list elements only by replacing them; does not modify `messages`
    in place. Safe to call on every turn.
    """
    if not messages:
        return messages

    out: list[dict[str, Any]] = []
    sys_idx: int | None = None
    first_user_idx: int | None = None
    for i, m in enumerate(messages):
        out.append(dict(m))
        if sys_idx is None and m.get("role") == "system":
            sys_idx = i
        elif first_user_idx is None and m.get("role") == "user":
            first_user_idx = i

    last_idx = len(out) - 1

    for idx in {sys_idx, first_user_idx, last_idx}:
        if idx is None:
            continue
        out[idx] = _mark(out[idx])

    return out


def _mark(message: dict[str, Any]) -> dict[str, Any]:
    """Wrap a message's content in the structured form Anthropic requires
    for cache_control, when it isn't already structured."""
    content = message.get("content")
    if isinstance(content, list):
        if content:
            last = dict(content[-1])
            last["cache_control"] = CACHE_CONTROL
            content = list(content[:-1]) + [last]
            message["content"] = content
        return message
    if isinstance(content, str):
        message["content"] = [
            {"type": "text", "text": content, "cache_control": CACHE_CONTROL}
        ]
        return message
    return message
