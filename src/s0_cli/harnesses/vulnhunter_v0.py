"""Vulnhunter v0: LLM-driven novelty hunter for unknown vulnerabilities.

Different shape from `baseline_v0_agentic`. The baseline harness *triages*
findings produced by classic scanners — it post-filters known signal. This
harness goes the other way: it starts from **zero scanner findings** and
uses the LLM to discover vulnerability classes that pattern matchers do not
have rules for.

Target classes (priority order):
  1. SSRF (CWE-918)
  2. Indirect RCE: SSTI, deserialization, plugin loaders (CWE-94, -502)
  3. IDOR / broken object-level authorization (CWE-639)
  4. Authentication / session bypass (CWE-287, -862)
  5. Race conditions / TOCTOU (CWE-367)
  6. Mass-assignment / unsafe ORM use (CWE-915)
  7. Subtle crypto mistakes (IV reuse, ECB, weak HMAC compare) (CWE-327)
  8. Path traversal through `os.path.join` / `Path` quirks (CWE-22)

Strategy:
  1. Build env snapshot.
  2. Skip seed scanners — we want pure LLM novelty.
  3. Hand the agent a "map attack surface, then trace each entry point"
     prompt with the full read-only investigation toolkit (`grep_code`,
     `read_file`, `list_files`, `git_blame`).
  4. The agent emits `add_finding` with `vulnhunter-*` rule IDs; downstream
     dedup collapses any overlap with classic scanner findings via
     `Finding.fingerprint()` (path, line, rule_family).

Pareto role: high-cost, high-novelty. Pair with `baseline_v0_agentic`
when you want both "calibrate the known" and "find the unknown".

The proposer can mutate the prompt, max_turns, the entry-point grep
strategy, the rubric, or which CWE classes are in scope. The contract
the proposer must preserve is: returns Findings with `source`
starting `"vulnhunter"`, `rule_id` starting `"vulnhunter-"`, and at
most `max_turns` agent turns.
"""

from __future__ import annotations

from s0_cli.config import get_settings
from s0_cli.harness.base import Harness, ScanResult
from s0_cli.harness.bootstrap import env_snapshot
from s0_cli.harness.llm import LLM
from s0_cli.harness.loop import agent_loop
from s0_cli.harness.progress import emit as _emit
from s0_cli.harness.tools import ToolContext, Tools
from s0_cli.prompts import load as load_prompt
from s0_cli.targets.base import Target

_TOOLS_SUMMARY = (
    "- read_file(path, start_line, end_line): inspect source\n"
    "- grep_code(pattern, glob): regex search across the target\n"
    "- list_files(dir): list files recursively\n"
    "- git_blame(path, start, end): who introduced this line\n"
    "- run_scanner(name): re-run a registered scanner if you need confirmation\n"
    "- add_finding(...): promote a vulnerability to the report\n"
    "- mark_false_positive(fingerprint, reason): dedup or suppress\n"
    "- task_complete(reason): END the loop"
)


class VulnhunterV0(Harness):
    name = "vulnhunter_v0"
    description = "LLM-driven novelty hunter (SSRF/RCE/IDOR/auth/race/crypto/path)."
    max_turns = 25
    token_budget = 250_000
    output_cap_bytes = 30_000
    # Empty by design: this harness deliberately does NOT consume scanner
    # seeds. Pair with `baseline_v0_agentic` (which DOES) when you want
    # complete coverage.
    default_scanners = ()

    def __init__(self) -> None:
        settings = get_settings()
        self._settings = settings
        self._llm = LLM(
            model=settings.model,
            temperature=settings.temperature,
            request_timeout_sec=settings.request_timeout_sec,
            no_llm=False,
        )

    def with_no_llm(self) -> VulnhunterV0:
        # In --no-llm mode, this harness produces no findings (by design;
        # there's no deterministic fallback for "novel vuln class detection").
        # The `baseline_v0_agentic` harness should be used for hermetic eval.
        self._llm.no_llm = True
        return self

    async def scan(self, target: Target) -> ScanResult:
        _emit("phase_start", name="env_snapshot")
        env = await env_snapshot(target)
        _emit("phase_done", name="env_snapshot", file_count=env.file_count)

        ctx = ToolContext(target=target, output_cap_bytes=self.output_cap_bytes)
        tools = Tools(ctx)

        system_prompt = load_prompt("vulnhunter_v0.txt").format(
            env=env.to_text(),
            tools_summary=_TOOLS_SUMMARY,
            max_turns=self.max_turns,
        )
        user_prompt = (
            f"Hunt {target.display()!r} for the eight vulnerability classes "
            f"listed in your system prompt. Start by mapping every HTTP route "
            f"and message-handler entry point with grep_code, then trace each "
            f"one for tainted-data flow into a dangerous sink. Call "
            f"task_complete when done."
        )

        _emit("phase_start", name="agent_loop", max_turns=self.max_turns)
        loop_result = await agent_loop(
            llm=self._llm,
            tools=tools,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            tool_schemas=Tools.SCHEMAS,
            max_turns=self.max_turns,
            token_budget=self.token_budget,
        )
        _emit(
            "phase_done",
            name="agent_loop",
            turns=loop_result.usage.get("turns", 0),
            ended_via=loop_result.ended_via,
            findings=len(loop_result.findings),
        )

        # Re-tag any findings the model didn't prefix correctly so they
        # sort/group cleanly with the rest of the vulnhunter output.
        normalized = [_normalize_source(f) for f in loop_result.findings]

        return ScanResult(
            findings=normalized,
            trace=loop_result.trace,
            usage=loop_result.usage,
            ended_via=loop_result.ended_via,
        )


def _normalize_source(finding):
    """Ensure every emitted finding is identifiable as vulnhunter output."""
    from dataclasses import replace
    new_source = finding.source
    if not new_source.startswith("vulnhunter"):
        new_source = f"vulnhunter:{new_source}" if new_source else "vulnhunter"
    new_rule = finding.rule_id
    if not new_rule.startswith("vulnhunter-"):
        new_rule = f"vulnhunter-{new_rule.lstrip('-')}"
    if new_source == finding.source and new_rule == finding.rule_id:
        return finding
    return replace(finding, source=new_source, rule_id=new_rule)
