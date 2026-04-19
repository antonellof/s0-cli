# Proposer Skill: writing a new s0-cli inner harness

You are the **proposer** in the outer Meta-Harness loop ([Lee et al., 2026, §3](https://arxiv.org/abs/2603.28052)). Your job is to write a new single-file inner harness for s0-cli that improves on prior candidates as measured by the evaluator.

This skill defines: your interface contract, what is forbidden, how to inspect prior experience, and what the objective is.

## Your task each iteration

1. **Inspect prior experience** in `runs/`. Use the `s0 runs` CLI rather than ad-hoc `find`/`grep`. Read raw traces, not just scores (paper Table 3 ablation: traces are the key signal).
2. **Diagnose** failure modes across prior candidates. Form a causal hypothesis. Reference specific run IDs and trace files in your reasoning.
3. **Write** a new harness file at `src/s0_cli/harnesses/<your_name>.py` and (if needed) a matching prompt template at `src/s0_cli/prompts/<your_name>.txt`.
4. **Validate** your harness with `uv run s0 eval --validate-only --harness <your_name>` before requesting full evaluation.

## Interface contract (must satisfy)

Your harness file must:

- Define exactly one class subclassing `s0_cli.harness.base.Harness`.
- Set `name = "<your_name>"` (must match the filename).
- Implement `async def scan(self, target: Target) -> ScanResult`.
- Use only tools from `s0_cli.harness.tools.Tools` — do not import scanners directly, do not exec/subprocess on your own.
- Be self-contained in one file (you may import from `s0_cli.harness.*` and `s0_cli.scanners.*` types, but no other harness files).
- Run within budgets: `max_turns`, `token_budget`, `output_cap_bytes` (set as class attributes).

## Forbidden paths (do NOT modify or read for cheating)

- `bench/**` — labeled tasks. Reading ground truth would let you cheat.
- `src/s0_cli/eval/**` — evaluator and scorer. Don't game the metric.
- `src/s0_cli/scanners/**` — scanner integrations. Treat as fixed tools.
- `src/s0_cli/runs/store.py` — run-store schema. Don't change the API the proposer reads.
- `runs/<other_harness>/traces/**/findings.json` is fine to read; `runs/**/ground_truth.json` is also fine (it's already in `bench/` and gets copied per-trace as a label, not as input to your harness at scan time).

You **may** create new files under `src/s0_cli/harnesses/` and `src/s0_cli/prompts/`.

## Objective

Maximize the search-set **F1 weighted by severity** (computed by `eval/scorer.py`), subject to a soft `tokens_per_task` budget. Secondary: latency, dollar cost, false-positive rate.

The evaluator returns a `score.json` with all of these. Pareto improvements are valued — i.e. a harness with same F1 at half the tokens is a win.

## How to query prior experience

Use the `s0 runs` CLI; it is faster than `find` and aligned with how coding agents are trained:

```bash
s0 runs list                       # all runs, newest first
s0 runs list --frontier            # only the Pareto frontier (F1 vs tokens)
s0 runs show <run_id>              # score, summary, harness diff vs parent
s0 runs diff <run_a> <run_b>       # side-by-side harness + score diff
s0 runs grep "<regex>"             # ripgrep across all traces
s0 runs tail-traces <run_id> <task_id>   # raw prompts/responses for one task
```

When forming a hypothesis, **read at least 3-5 prior trace files** for the failure mode you suspect. The paper §A.1 reports a median of 82 file reads per iteration in the tbench2 setting. Don't optimize from scores alone — that's the ablation that loses 15 points.

## Search-space hints (not requirements)

Things prior harnesses have gotten wrong; consider edits along these axes:

- **Scanner selection.** Which scanners to run, in what order, with what filtering of their output before the LLM sees it.
- **Tool budget.** Turn cap per task, retry strategy on tool errors, when to give up.
- **Prompt structure.** System prompt wording, in-context exemplars of correct triage, severity calibration rubric, fix-hint style.
- **Dedup heuristic.** How findings are fingerprinted across scanners and across runs.
- **Severity recalibration.** Reachability-aware reweighting (admin route vs public, test code vs prod, etc.).
- **Investigation policy.** When to `read_file` deeper, when to `git_blame`, when to `grep_code` for taint, when to stop.
- **Vibe-code heuristics.** When to invoke LLM-only detectors vs trust classic scanners.

## Anti-patterns observed in prior runs

- Hardcoding bench task names, file paths, or rule_ids: instant disqualification on held-out (Phase 4).
- Reading ground truth from `runs/**/ground_truth.json` and echoing it as findings: same.
- Disabling the turn cap: causes infinite loops on hard tasks; budget exists for a reason.
- Removing the env_snapshot: paper §A.2 iterations 1-6 all regressed when the bootstrap was tampered with.

## Style

- Aim for <500 lines per harness file. The Meta-Harness paper §B reports 100-1000 LOC; smaller is easier to diagnose.
- Heavy comments at the top of the file: hypothesis, what changed vs parent, expected effect.
- Prefer additive changes over rewrites (paper §A.2 iteration 7: "purely additive" was the winning strategy after 6 regressions).
