"""Baseline v0 (agentic): KIRA-shaped multi-turn investigator.

This is one of the two seeds the Phase-1 outer loop will start from. It is
intentionally close to the KRAFTON KIRA layout: native litellm tool calling,
prompt caching, multi-turn loop with budget caps. The Pareto role is the
**accuracy anchor** — high cost, high precision/recall.

Strategy:
  1. Build env snapshot.
  2. Run semgrep to seed candidate findings.
  3. Hand the candidates + env to the LLM with the full investigation toolkit.
  4. Loop until the LLM calls `task_complete` or budget is exhausted.
  5. Return whatever findings the LLM promoted via `add_finding`.

The proposer can mutate any of: prompt template, scanner selection, tool subset,
turn cap, what it does with falsy/empty seeds, post-processing, etc.
"""

from __future__ import annotations

from s0_cli.config import get_settings
from s0_cli.harness.base import Harness, ScanResult
from s0_cli.harness.bootstrap import env_snapshot
from s0_cli.harness.llm import LLM
from s0_cli.harness.loop import agent_loop
from s0_cli.harness.tools import ToolContext, Tools, _finding_summary
from s0_cli.prompts import load as load_prompt
from s0_cli.scanners import REGISTRY as SCANNER_REGISTRY
from s0_cli.scanners.base import Finding
from s0_cli.targets.base import Target


class BaselineV0Agentic(Harness):
    name = "baseline_v0_agentic"
    description = "KIRA-style multi-turn investigator over multi-scanner candidates."
    max_turns = 30
    token_budget = 200_000
    output_cap_bytes = 30_000
    default_scanners = ("semgrep", "bandit", "ruff", "gitleaks", "trivy")

    def __init__(self) -> None:
        settings = get_settings()
        self._settings = settings
        self._llm = LLM(
            model=settings.model,
            temperature=settings.temperature,
            request_timeout_sec=settings.request_timeout_sec,
            no_llm=False,
        )

    def with_no_llm(self) -> BaselineV0Agentic:
        self._llm.no_llm = True
        return self

    async def scan(self, target: Target) -> ScanResult:
        env = await env_snapshot(target)
        seed_findings = _seed_from_scanners(self.default_scanners, target)

        ctx = ToolContext(target=target, output_cap_bytes=self.output_cap_bytes)
        tools = Tools(ctx)

        system_prompt = load_prompt("baseline_v0_agentic.txt").format(
            env=env.to_text(),
            scanners=", ".join(sorted(SCANNER_REGISTRY.keys())),
            seed_findings=_render_seeds(seed_findings),
            max_turns=self.max_turns,
        )
        user_prompt = (
            f"Triage the {len(seed_findings)} candidate findings above for target "
            f"{target.display()!r}. Use the tools to verify reachability and severity, "
            f"sweep for vibe-code patterns, then call task_complete."
        )

        loop_result = await agent_loop(
            llm=self._llm,
            tools=tools,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            tool_schemas=Tools.SCHEMAS,
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


def _seed_from_scanners(names: tuple[str, ...], target: Target) -> list[Finding]:
    """Run every available scanner and dedupe findings cross-tool.

    Two findings are considered duplicates when they share (path, line,
    rule_id_normalized). Cross-tool duplicates (e.g. semgrep + bandit both
    flagging the same `subprocess(shell=True)` line) get collapsed; the
    higher-confidence one wins. Skipping a missing binary is silent — the
    LLM still sees a `seed_findings` list, just shorter.
    """
    deduped: dict[tuple[str, int, str], Finding] = {}
    for name in names:
        scanner_cls = SCANNER_REGISTRY.get(name)
        if scanner_cls is None:
            continue
        scanner = scanner_cls()
        if not scanner.is_available():
            continue
        try:
            findings = scanner.run(target)
        except Exception as e:  # noqa: BLE001 — seed-phase isolation
            print(f"warning: seed scanner {name!r} failed: {type(e).__name__}: {e}")
            continue
        for f in findings:
            key = (f.path, f.line, _normalize_rule(f.rule_id))
            existing = deduped.get(key)
            if existing is None or f.confidence > existing.confidence:
                deduped[key] = f
    return sorted(deduped.values(), key=lambda f: (f.path, f.line, f.rule_id))


def _normalize_rule(rule_id: str) -> str:
    """Strip vendor/family prefixes so cross-tool dedup actually catches dupes."""
    rid = rule_id.lower()
    for prefix in ("python.", "javascript.", "java.", "go.", "rules."):
        if rid.startswith(prefix):
            rid = rid[len(prefix):]
    return rid.split(".")[-1]


def _render_seeds(seeds: list) -> str:
    if not seeds:
        return "(no scanner findings; sweep for vibe-code patterns yourself)"
    lines = []
    for f in seeds[:80]:
        s = _finding_summary(f)
        lines.append(
            f"- [{s['severity']}] {s['rule_id']} {s['path']}:{s['line']} "
            f"({s['source']}) — {s['message'][:160]}"
        )
        if s.get("snippet"):
            lines.append(f"    > {s['snippet'][:160]}")
    if len(seeds) > 80:
        lines.append(f"... and {len(seeds) - 80} more candidates.")
    return "\n".join(lines)
