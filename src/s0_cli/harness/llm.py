"""Thin litellm wrapper.

Handles:
- async chat completion with native tool calling
- retry on transient errors
- normalization of the response (content + tool_calls + usage)
- context-overflow detection (raised as `ContextOverflowError` for the loop to summarize)
- a `--no-llm` mode where every call returns a deterministic stub (for tests / CI)

Kept intentionally small. Harnesses do not depend on litellm directly; they
only see this `LLM` class. That makes it easy for the Phase-1 proposer to
reason about cost.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from s0_cli.harness.anthropic_caching import add_anthropic_caching


class LLMError(RuntimeError):
    pass


class ContextOverflowError(LLMError):
    pass


class AuthError(LLMError):
    pass


@dataclass
class LLMResponse:
    content: str | None
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    reasoning: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    cached_input_tokens: int = 0
    finish_reason: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class LLM:
    model: str
    temperature: float = 0.0
    request_timeout_sec: int = 120
    no_llm: bool = False

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict[str, Any] | None = None,
    ) -> LLMResponse:
        if self.no_llm:
            return _stub_response(tools)

        try:
            import litellm
        except ImportError as e:
            raise LLMError(
                "litellm is not installed. `uv sync` or set --no-llm."
            ) from e

        from litellm.exceptions import (
            APIConnectionError,
            APIError,
            AuthenticationError,
            BadRequestError,
            ContextWindowExceededError,
            RateLimitError,
            ServiceUnavailableError,
            Timeout,
        )

        cached_messages = add_anthropic_caching(messages)

        async for attempt in AsyncRetrying(
            wait=wait_exponential(multiplier=1, min=2, max=30),
            stop=stop_after_attempt(4),
            retry=retry_if_exception_type(
                (APIConnectionError, RateLimitError, ServiceUnavailableError, Timeout)
            ),
            reraise=True,
        ):
            with attempt:
                try:
                    resp = await litellm.acompletion(
                        model=self.model,
                        messages=cached_messages,
                        tools=tools,
                        tool_choice=tool_choice,
                        temperature=self.temperature,
                        timeout=self.request_timeout_sec,
                    )
                except ContextWindowExceededError as e:
                    raise ContextOverflowError(str(e)) from e
                except AuthenticationError as e:
                    raise AuthError(str(e)) from e
                except BadRequestError as e:
                    msg = str(e).lower()
                    if "context" in msg and ("length" in msg or "window" in msg):
                        raise ContextOverflowError(str(e)) from e
                    raise LLMError(str(e)) from e
                except APIError as e:
                    raise LLMError(str(e)) from e

        return _normalize_response(resp)


def _normalize_response(resp: Any) -> LLMResponse:
    msg = resp.choices[0].message
    content = getattr(msg, "content", None)
    tool_calls_raw = getattr(msg, "tool_calls", None) or []
    tool_calls: list[dict[str, Any]] = []
    for tc in tool_calls_raw:
        fn = getattr(tc, "function", None) or tc.get("function", {})
        name = getattr(fn, "name", None) if not isinstance(fn, dict) else fn.get("name")
        args_raw = (
            getattr(fn, "arguments", None) if not isinstance(fn, dict) else fn.get("arguments")
        )
        try:
            args = json.loads(args_raw) if isinstance(args_raw, str) else (args_raw or {})
        except json.JSONDecodeError:
            args = {"_raw": args_raw}
        tool_calls.append(
            {
                "id": getattr(tc, "id", None) if not isinstance(tc, dict) else tc.get("id"),
                "name": name,
                "arguments": args,
            }
        )

    usage = getattr(resp, "usage", None)
    in_tok = getattr(usage, "prompt_tokens", 0) if usage else 0
    out_tok = getattr(usage, "completion_tokens", 0) if usage else 0
    cached = 0
    if usage is not None:
        cached = (
            getattr(usage, "cache_read_input_tokens", 0)
            or getattr(usage, "prompt_cache_hit_tokens", 0)
            or 0
        )

    return LLMResponse(
        content=content,
        tool_calls=tool_calls,
        reasoning=getattr(msg, "reasoning_content", None),
        input_tokens=in_tok,
        output_tokens=out_tok,
        cached_input_tokens=cached,
        finish_reason=getattr(resp.choices[0], "finish_reason", None),
        raw={},
    )


def _stub_response(tools: list[dict[str, Any]] | None) -> LLMResponse:
    """Deterministic response for --no-llm / tests.

    Strategy: if `task_complete` is among the tools, call it. Otherwise return
    a tiny content message. This lets the agent loop terminate cleanly without
    a real model.
    """
    if tools:
        for t in tools:
            fn = t.get("function", {})
            if fn.get("name") == "task_complete":
                return LLMResponse(
                    content=None,
                    tool_calls=[
                        {"id": "stub-0", "name": "task_complete", "arguments": {}}
                    ],
                    finish_reason="tool_calls",
                )
    return LLMResponse(content="(no-llm stub: nothing to do)", finish_reason="stop")


def have_provider_key(model: str) -> bool:
    """Best-effort check that an API key is present for the given model."""
    if model.startswith("anthropic/"):
        return bool(os.environ.get("ANTHROPIC_API_KEY"))
    if model.startswith("openai/") or model.startswith("gpt-"):
        return bool(os.environ.get("OPENAI_API_KEY"))
    if model.startswith("gemini/") or model.startswith("vertex_ai/"):
        return bool(os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"))
    return True
