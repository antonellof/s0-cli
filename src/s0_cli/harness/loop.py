"""KIRA-style multi-turn agent loop, stripped of tmux / image-read.

Responsibilities:
- Send messages + tools to the LLM via the `LLM` wrapper
- Dispatch tool calls through the `Tools` instance
- Append tool results to message history
- Track turn count, token usage, and termination conditions
- On context overflow: summarize older turns and retry once
- Record every step into a structured trace

The harness file owns the *policy* (which tools, what system prompt, what
budgets); this loop owns the *mechanics*. That split is what lets the Phase-1
proposer rewrite the harness without breaking the loop semantics.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from s0_cli.harness.llm import LLM, ContextOverflowError, is_reasoning_model
from s0_cli.harness.progress import emit as _emit
from s0_cli.harness.tools import ToolCallRecord, Tools


@dataclass
class LoopResult:
    findings: list[Any] = field(default_factory=list)
    suppressed: list[str] = field(default_factory=list)
    trace: list[dict[str, Any]] = field(default_factory=list)
    usage: dict[str, int | float] = field(default_factory=dict)
    ended_via: str = "task_complete"
    turns: int = 0


async def agent_loop(
    *,
    llm: LLM,
    tools: Tools,
    system_prompt: str,
    user_prompt: str,
    tool_schemas: list[dict[str, Any]],
    max_turns: int = 30,
    token_budget: int = 200_000,
    force_tool_choice: str | dict[str, Any] | None = None,
) -> LoopResult:
    """Drive the LLM through a tool-using loop until completion or budget.

    Parameters mirror what a harness wants to control. Returns a `LoopResult`
    that the harness folds into a `ScanResult`.
    """
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    trace: list[dict[str, Any]] = []
    total_in = 0
    total_out = 0
    total_cached = 0
    turn = 0
    ended_via = "budget_exhausted"
    summarized_once = False

    model_is_reasoning = is_reasoning_model(llm.model)

    while turn < max_turns:
        turn += 1
        t0 = time.monotonic()
        _emit(
            "llm_turn_start",
            turn=turn,
            max_turns=max_turns,
            tokens_in=total_in,
            tokens_out=total_out,
            is_reasoning=model_is_reasoning,
            model=llm.model,
        )

        try:
            resp = await llm.complete(
                messages=messages,
                tools=tool_schemas,
                tool_choice=force_tool_choice,
            )
        except ContextOverflowError as e:
            if summarized_once:
                trace.append(
                    {
                        "type": "error",
                        "turn": turn,
                        "error": f"ContextOverflow after summary: {e}",
                    }
                )
                ended_via = "error:context_overflow"
                break
            messages = _summarize_history(messages, llm.model)
            summarized_once = True
            trace.append({"type": "summarize", "turn": turn, "reason": str(e)})
            continue
        except Exception as e:
            trace.append(
                {
                    "type": "error",
                    "turn": turn,
                    "error": f"{type(e).__name__}: {e}",
                }
            )
            ended_via = f"error:{type(e).__name__}"
            break

        elapsed_ms = int((time.monotonic() - t0) * 1000)
        total_in += resp.input_tokens
        total_out += resp.output_tokens
        total_cached += resp.cached_input_tokens

        # Once we observe actual reasoning content/tokens, latch the
        # reasoning flag for subsequent turns so the spinner stays in
        # "thinking…" mode even if the name heuristic missed.
        if resp.reasoning_tokens > 0 or resp.reasoning:
            model_is_reasoning = True

        _emit(
            "llm_turn_done",
            turn=turn,
            duration_ms=elapsed_ms,
            input_tokens=resp.input_tokens,
            output_tokens=resp.output_tokens,
            reasoning_tokens=resp.reasoning_tokens,
            tool_calls=[tc["name"] for tc in resp.tool_calls],
            finish_reason=resp.finish_reason,
            is_reasoning=model_is_reasoning,
        )

        trace.append(
            {
                "type": "llm_call",
                "turn": turn,
                "input_tokens": resp.input_tokens,
                "output_tokens": resp.output_tokens,
                "cached_input_tokens": resp.cached_input_tokens,
                "finish_reason": resp.finish_reason,
                "duration_ms": elapsed_ms,
                "content_preview": (resp.content or "")[:240],
                "tool_calls": [
                    {"name": tc["name"], "arguments": tc.get("arguments", {})}
                    for tc in resp.tool_calls
                ],
            }
        )

        assistant_msg: dict[str, Any] = {"role": "assistant"}
        if resp.content:
            assistant_msg["content"] = resp.content
        if resp.tool_calls:
            assistant_msg["tool_calls"] = [
                {
                    "id": tc["id"] or f"call_{turn}_{i}",
                    "type": "function",
                    "function": {
                        "name": tc["name"],
                        "arguments": json.dumps(tc.get("arguments", {})),
                    },
                }
                for i, tc in enumerate(resp.tool_calls)
            ]
        messages.append(assistant_msg)

        if not resp.tool_calls:
            ended_via = "no_tool_calls"
            break

        for i, tc in enumerate(resp.tool_calls):
            ts = time.monotonic()
            _emit(
                "tool_call_start",
                turn=turn,
                name=tc["name"],
                arguments=tc.get("arguments", {}),
            )
            result = tools.dispatch(tc["name"], tc.get("arguments", {}))
            tool_dur = int((time.monotonic() - ts) * 1000)
            _emit(
                "tool_call_done",
                turn=turn,
                name=tc["name"],
                duration_ms=tool_dur,
            )
            tools.ctx.trace.append(
                ToolCallRecord(
                    name=tc["name"],
                    arguments=tc.get("arguments", {}),
                    result=result if isinstance(result, dict) else {"result": str(result)},
                    duration_ms=tool_dur,
                )
            )
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc["id"] or f"call_{turn}_{i}",
                    "name": tc["name"],
                    "content": _serialize_tool_result(result),
                }
            )

        if tools.ctx.completed:
            ended_via = "task_complete"
            break

        if total_in + total_out > token_budget:
            ended_via = "budget_exhausted:tokens"
            break

    return LoopResult(
        findings=list(tools.ctx.findings),
        suppressed=list(tools.ctx.suppressed),
        trace=trace,
        usage={
            "input_tokens": total_in,
            "output_tokens": total_out,
            "cached_input_tokens": total_cached,
            "turns": turn,
        },
        ended_via=ended_via,
        turns=turn,
    )


def _serialize_tool_result(result: Any) -> str:
    if isinstance(result, str):
        return result
    try:
        return json.dumps(result, default=str)
    except (TypeError, ValueError):
        return str(result)


def _summarize_history(
    messages: list[dict[str, Any]], _model: str
) -> list[dict[str, Any]]:
    """Compress middle of the conversation to a single user note.

    Cheap heuristic, not an LLM call: keep system, first user, last 4 messages,
    drop everything else. The paper's full version uses an LLM summarizer; this
    is good enough in practice and avoids another round-trip.
    """
    if len(messages) <= 6:
        return messages
    head = messages[:2]
    tail = messages[-4:]
    dropped = len(messages) - len(head) - len(tail)
    note = {
        "role": "user",
        "content": (
            f"[Context summary: {dropped} earlier turns elided to fit the model's "
            f"context window. Continue the triage based on the recent messages and "
            f"the original task. Findings already added are preserved.]"
        ),
    }
    return [*head, note, *tail]
