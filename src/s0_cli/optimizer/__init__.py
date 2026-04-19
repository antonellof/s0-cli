"""Outer Meta-Harness loop.

A coding-agent proposer reads `runs/` (prior harness candidates + scores +
traces), reads `SKILL.md`, and writes a new `src/s0_cli/harnesses/<name>.py`
that should improve on the Pareto frontier of (F1, tokens) on the bench.

Then this module drives:

    while iterations_remaining and time_remaining:
        ctx = build_context(runs_dir, skill_md, top_k=4)
        new_harness_path = proposer.propose(ctx)            # LLM agent
        report = validate_harness(new_harness_path)         # static checks
        if not report.ok:
            log_failed_proposal(report)
            continue
        eval_summary = eval_runner.run(harness)             # writes a run
        log_iteration(eval_summary)

Single-file harnesses, filesystem-only experience store, validated proposals.
Aligned with Lee et al. (2026), section 3 (loop) and section D (CLI).
"""

from s0_cli.optimizer.context import OptimizerContext, build_context
from s0_cli.optimizer.loop import OptimizerResult, run_optimizer
from s0_cli.optimizer.proposer import Proposer, ProposerOutput

__all__ = [
    "OptimizerContext",
    "build_context",
    "Proposer",
    "ProposerOutput",
    "OptimizerResult",
    "run_optimizer",
]
