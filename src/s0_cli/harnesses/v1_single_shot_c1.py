"""Single-shot triage with reduced token usage.

Proposer-generated harness. Produced on 2026-04-19 by `s0 optimize -n 2 -k 2`
running gpt-4o-mini against `bench/tasks_train/`; selected as the iter-1 winner
(train F1 0.476, held-out test F1 0.667 vs baseline_v0_singleshot's ~0.59 test
F1). See [docs/results/REAL_WORLD_RESULTS.md](../../../docs/results/REAL_WORLD_RESULTS.md)
for the full session and the diff against `baseline_v0_singleshot.py`.

Builds on `baseline_v0_singleshot` by shortening the user prompt — the only
substantive edit is collapsing the per-scan instruction from "Decide which of
the {n} candidates to keep, then call task_complete. No investigation tools
available." to "Triage the {n} candidates and call task_complete." — saving
~10 tokens per scan while improving held-out F1.
"""

from __future__ import annotations

import time

from s0_cli.config import get_settings
from s0_cli.harness.base import Harness, ScanResult
from s0_cli.harness.bootstrap import env_snapshot
from s0_cli.harness.llm import LLM
from s0_cli.harness.loop import agent_loop
from s0_cli.harness.progress import emit as _emit
from s0_cli.harness.tools import ToolContext, Tools, _finding_summary
from s0_cli.prompts import load as load_prompt
from s0_cli.scanners.semgrep import SemgrepScanner
from s0_cli.targets.base import Target


class V1SingleShotC1(Harness):
    name = "v1_single_shot_c1"
    description = "Single-shot triage with reduced token usage."
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

    def with_no_llm(self) -> V1SingleShotC1:
        self._llm.no_llm = True
        return self

    async def scan(self, target: Target) -> ScanResult:
        _emit("phase_start", name="env_snapshot")
        env = await env_snapshot(target)
        _emit("phase_done", name="env_snapshot", file_count=env.file_count)

        scanner = SemgrepScanner()
        if scanner.is_available():
            _emit("scanner_start", name="semgrep", index=1, total=1)
            t0 = time.monotonic()
            seed_findings = scanner.run(target)
            _emit(
                "scanner_done",
                name="semgrep",
                index=1,
                total=1,
                findings=len(seed_findings),
                duration_ms=int((time.monotonic() - t0) * 1000),
            )
        else:
            _emit("scanner_skip", name="semgrep", reason="not_installed", index=1, total=1)
            seed_findings = []

        ctx = ToolContext(target=target, output_cap_bytes=self.output_cap_bytes)
        tools = Tools(ctx)

        system_prompt = load_prompt("baseline_v0_singleshot.txt").format(
            env=env.to_text(),
            seed_findings=_render_seeds(seed_findings),
        )
        user_prompt = (
            f"Triage the {len(seed_findings)} candidates and call task_complete."
        )

        _emit("phase_start", name="agent_loop", max_turns=self.max_turns)
        loop_result = await agent_loop(
            llm=self._llm,
            tools=tools,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            tool_schemas=Tools.SINGLESHOT_SCHEMAS,
            max_turns=self.max_turns,
            token_budget=self.token_budget,
        )
        _emit(
            "phase_done",
            name="agent_loop",
            turns=loop_result.usage.get("turns", 0),
            ended_via=loop_result.ended_via,
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
            f"({s['source']})  {s['message'][:200]}"
        )
        if s.get("snippet"):
            lines.append(f"    > {s['snippet'][:160]}")
    if len(seeds) > 120:
        lines.append(f"... and {len(seeds) - 120} more candidates (consider keeping all of them).")
    return "\n".join(lines)
