"""Baseline v0 (single-shot): cost-anchor seed.

One LLM call, two tools (`add_finding`, `task_complete`), no investigation.
Pareto role: cheapest possible LLM-triaged scan. The proposer should be able
to *beat* this on accuracy by spending more turns; if it can't, keep this.
"""

from __future__ import annotations

from s0_cli.config import get_settings
from s0_cli.harness.base import Harness, ScanResult
from s0_cli.harness.bootstrap import env_snapshot
from s0_cli.harness.llm import LLM
from s0_cli.harness.loop import agent_loop
from s0_cli.harness.tools import ToolContext, Tools, _finding_summary
from s0_cli.prompts import load as load_prompt
from s0_cli.scanners.semgrep import SemgrepScanner
from s0_cli.targets.base import Target


class BaselineV0SingleShot(Harness):
    name = "baseline_v0_singleshot"
    description = "Single-shot triage of semgrep candidates; Pareto cost anchor."
    max_turns = 1
    token_budget = 50_000
    output_cap_bytes = 30_000
    default_scanners = ("semgrep",)

    def __init__(self) -> None:
        settings = get_settings()
        self._settings = settings
        self._llm = LLM(
            model=settings.model,
            temperature=settings.temperature,
            request_timeout_sec=settings.request_timeout_sec,
            no_llm=False,
        )

    def with_no_llm(self) -> BaselineV0SingleShot:
        self._llm.no_llm = True
        return self

    async def scan(self, target: Target) -> ScanResult:
        env = await env_snapshot(target)

        scanner = SemgrepScanner()
        seed_findings = scanner.run(target) if scanner.is_available() else []

        ctx = ToolContext(target=target, output_cap_bytes=self.output_cap_bytes)
        tools = Tools(ctx)

        system_prompt = load_prompt("baseline_v0_singleshot.txt").format(
            env=env.to_text(),
            seed_findings=_render_seeds(seed_findings),
        )
        user_prompt = (
            f"Decide which of the {len(seed_findings)} candidates to keep, then call "
            f"task_complete. No investigation tools available."
        )

        loop_result = await agent_loop(
            llm=self._llm,
            tools=tools,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            tool_schemas=Tools.SINGLESHOT_SCHEMAS,
            max_turns=self.max_turns,
            token_budget=self.token_budget,
        )

        findings = loop_result.findings
        if not findings and seed_findings:
            findings = seed_findings

        return ScanResult(
            findings=list(findings),
            trace=loop_result.trace,
            usage=loop_result.usage,
            ended_via=loop_result.ended_via,
        )


def _render_seeds(seeds: list) -> str:
    if not seeds:
        return "(no candidates)"
    lines = []
    for f in seeds[:120]:
        s = _finding_summary(f)
        lines.append(
            f"- [{s['severity']}] {s['rule_id']} {s['path']}:{s['line']} "
            f"({s['source']}) — {s['message'][:200]}"
        )
        if s.get("snippet"):
            lines.append(f"    > {s['snippet'][:160]}")
    if len(seeds) > 120:
        lines.append(f"... and {len(seeds) - 120} more candidates (consider keeping all of them).")
    return "\n".join(lines)
