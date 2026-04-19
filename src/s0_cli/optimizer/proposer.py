"""The proposer: a multi-turn coding agent that writes a new inner harness.

Reuses the same `agent_loop` as the inner harnesses, but with a different
tool surface (the proposer-specific tools in `optimizer/tools.py`).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from s0_cli.config import get_settings
from s0_cli.harness.llm import LLM
from s0_cli.harness.loop import agent_loop
from s0_cli.optimizer.context import OptimizerContext
from s0_cli.optimizer.tools import ProposerToolContext, ProposerTools
from s0_cli.prompts import load as load_prompt


@dataclass
class ProposerOutput:
    success: bool
    harness_path: Path | None
    prompt_path: Path | None
    finish_summary: str
    trace: list[dict[str, Any]]
    usage: dict[str, Any]
    ended_via: str


class Proposer:
    """Wraps the agentic loop. One `propose()` call per outer-loop iteration."""

    def __init__(
        self,
        *,
        runs_dir: Path,
        harnesses_dir: Path,
        prompts_dir: Path,
        max_turns: int = 25,
        token_budget: int = 250_000,
        no_llm: bool = False,
    ):
        self.runs_dir = runs_dir
        self.harnesses_dir = harnesses_dir
        self.prompts_dir = prompts_dir
        self.max_turns = max_turns
        self.token_budget = token_budget

        settings = get_settings()
        self.llm = LLM(
            model=settings.model,
            temperature=settings.temperature,
            request_timeout_sec=settings.request_timeout_sec,
            no_llm=no_llm,
        )

    async def propose(self, context: OptimizerContext) -> ProposerOutput:
        ctx = ProposerToolContext(
            runs_dir=self.runs_dir,
            harnesses_dir=self.harnesses_dir,
            prompts_dir=self.prompts_dir,
            skill_md=context.skill_md,
            initial_summary=context.render(top_k=8),
        )
        tools = ProposerTools(ctx)

        system_prompt = load_prompt("proposer_v0.txt").format(
            skill_md=context.skill_md or "(SKILL.md missing)",
            initial_summary=context.render(top_k=8),
            max_turns=self.max_turns,
        )
        user_prompt = (
            "Diagnose the most impactful failure mode in prior runs and ship a small, "
            "additive new harness. Pick a name, write the file, then call finish."
        )

        loop_result = await agent_loop(
            llm=self.llm,
            tools=_AdaptedTools(ctx, tools),
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            tool_schemas=ProposerTools.SCHEMAS,
            max_turns=self.max_turns,
            token_budget=self.token_budget,
        )

        return ProposerOutput(
            success=ctx.finished and ctx.written_harness is not None,
            harness_path=ctx.written_harness,
            prompt_path=ctx.written_prompt,
            finish_summary=ctx.finish_summary,
            trace=loop_result.trace,
            usage=loop_result.usage,
            ended_via=loop_result.ended_via,
        )


class _AdaptedTools:
    """agent_loop expects a `Tools`-shaped object with `.dispatch` and `.ctx`.

    The proposer's tool context is different from the scanner's, but the
    loop only inspects `tools.ctx.completed`, `tools.ctx.findings`, and
    `tools.ctx.suppressed`. We expose proposer state through the same fields.
    """

    def __init__(self, proposer_ctx: ProposerToolContext, real: ProposerTools):
        self._real = real
        self.ctx = _AdaptedCtx(proposer_ctx)

    def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any] | str:
        result = self._real.dispatch(name, arguments)
        if name == "finish":
            self.ctx.completed = True
        return result


class _AdaptedCtx:
    def __init__(self, proposer_ctx: ProposerToolContext):
        self._p = proposer_ctx
        self.findings: list = []
        self.suppressed: list = []
        self.trace: list = proposer_ctx.trace
        self.completion_reason: str | None = None

    @property
    def completed(self) -> bool:
        return self._p.finished

    @completed.setter
    def completed(self, value: bool) -> None:
        self._p.finished = value
