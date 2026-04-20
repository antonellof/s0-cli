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
    reasoning_tokens: int = 0
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
    reasoning_toks = 0
    if usage is not None:
        cached = (
            getattr(usage, "cache_read_input_tokens", 0)
            or getattr(usage, "prompt_cache_hit_tokens", 0)
            or 0
        )
        # Reasoning tokens live under completion_tokens_details on
        # OpenAI/o-series + OpenRouter; some providers attach them flat.
        details = getattr(usage, "completion_tokens_details", None)
        if details is not None:
            reasoning_toks = (
                getattr(details, "reasoning_tokens", 0)
                if not isinstance(details, dict)
                else details.get("reasoning_tokens", 0)
            ) or 0
        if not reasoning_toks:
            reasoning_toks = getattr(usage, "reasoning_tokens", 0) or 0

    # Reasoning content surfaces under different keys per provider:
    # - OpenAI / DeepSeek: msg.reasoning_content
    # - Anthropic (extended thinking) / OpenRouter: msg.reasoning
    reasoning_text = (
        getattr(msg, "reasoning_content", None) or getattr(msg, "reasoning", None)
    )

    return LLMResponse(
        content=content,
        tool_calls=tool_calls,
        reasoning=reasoning_text,
        input_tokens=in_tok,
        output_tokens=out_tok,
        cached_input_tokens=cached,
        reasoning_tokens=int(reasoning_toks),
        finish_reason=getattr(resp.choices[0], "finish_reason", None),
        raw={},
    )


def _stub_response(tools: list[dict[str, Any]] | None) -> LLMResponse:
    """Deterministic response for --no-llm / tests.

    Strategy: if any termination tool (`task_complete`, `finish`) is among the
    available tools, call it with empty/minimal args. This lets any agent loop
    terminate cleanly without a real model.
    """
    if tools:
        for term_name in ("task_complete", "finish"):
            for t in tools:
                fn = t.get("function", {})
                if fn.get("name") == term_name:
                    args: dict[str, Any] = {}
                    if term_name == "finish":
                        args = {"summary": "(no-llm stub: no proposal made)"}
                    return LLMResponse(
                        content=None,
                        tool_calls=[
                            {"id": "stub-0", "name": term_name, "arguments": args}
                        ],
                        finish_reason="tool_calls",
                    )
    return LLMResponse(content="(no-llm stub: nothing to do)", finish_reason="stop")


def have_provider_key(model: str) -> bool:
    """Best-effort check that an API key is present for the given model.

    Returns ``True`` for providers that don't strictly require a key (notably
    a local Ollama install) so ``s0 doctor`` doesn't false-flag them.
    """
    if model.startswith("anthropic/"):
        return bool(os.environ.get("ANTHROPIC_API_KEY"))
    if model.startswith("openai/") or model.startswith("gpt-"):
        # OpenAI-compatible self-hosted endpoints (vLLM, llama.cpp, LM Studio,
        # …) speak the openai/ schema with OPENAI_API_BASE pointed at the
        # local URL — they don't always require a real key.
        return bool(
            os.environ.get("OPENAI_API_KEY")
            or os.environ.get("OPENAI_API_BASE")
        )
    if model.startswith("gemini/") or model.startswith("vertex_ai/"):
        return bool(os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"))
    if model.startswith("openrouter/"):
        return bool(os.environ.get("OPENROUTER_API_KEY"))
    if model.startswith("ollama/") or model.startswith("ollama_chat/"):
        # Local Ollama needs no key. Cloud-hosted Ollama proxies that require
        # OLLAMA_API_KEY will still fail at request time with a clear 401, so
        # we don't gate on it here.
        return True
    if model.startswith("groq/"):
        return bool(os.environ.get("GROQ_API_KEY"))
    if model.startswith("mistral/"):
        return bool(os.environ.get("MISTRAL_API_KEY"))
    if model.startswith("deepseek/"):
        return bool(os.environ.get("DEEPSEEK_API_KEY"))
    if model.startswith("azure/"):
        return bool(os.environ.get("AZURE_API_KEY") and os.environ.get("AZURE_API_BASE"))
    return True


# Substrings that mark a model as a reasoning / thinking model. These models
# spend significant wall-time before emitting any tokens, so the CLI swaps
# the spinner from "waiting on LLM…" to "thinking…" so the user knows what's
# happening. We deliberately accept some false positives — the worst case is
# a slightly different spinner label.
_REASONING_HINTS: tuple[str, ...] = (
    # OpenAI o-series (o1, o3, o4) + GPT-5 reasoning
    "o1-",
    "o3-",
    "o4-",
    "/o1",
    "/o3",
    "/o4",
    "gpt-5",
    # Anthropic extended thinking
    "thinking",
    # DeepSeek reasoner
    "deepseek-r1",
    "deepseek-reasoner",
    # Google
    "gemini-2.0-flash-thinking",
    "gemini-2.5-pro",  # native thinking on
    # Qwen QwQ / Marco-o1
    "qwq",
    "marco-o1",
)


def is_reasoning_model(model: str) -> bool:
    """Heuristic: does this model spend wall-time reasoning before answering?

    Used by the CLI progress sink to render a "thinking…" indicator instead
    of "waiting on LLM…". Detection is by name substring; the runtime sink
    also flips into thinking mode if any response carries actual reasoning
    content/tokens, so a missed pattern here self-corrects after turn 1.
    """
    if not model:
        return False
    m = model.lower()
    return any(hint in m for hint in _REASONING_HINTS)
