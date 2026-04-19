# s0-cli (Security-Zero)

> **Status:** Phase 0 scaffold. Two seed harnesses, one working scanner (semgrep), end-to-end evaluator, run-store, query CLI. No outer optimizer yet.

A command-line agent for scanning code for security vulnerabilities and "vibe-code" issues (AI-slop patterns: stub auth, hallucinated imports, prompt-injection sinks, etc.).

The architecture is intentionally **Meta-Harness-shaped** ([Lee et al., 2026](https://arxiv.org/abs/2603.28052)) so the scanning agent can be optimized end-to-end by an outer search loop in Phase 1, with the seed harnesses borrowing the [KIRA](https://github.com/krafton-ai/KIRA) layout (single-file harness, native litellm tool calling, prompt caching).

## Quickstart

```bash
uv sync
cp .env.example .env   # add ANTHROPIC_API_KEY (or set S0_MODEL to your provider)

# Scan a directory with the default agentic harness
uv run s0 scan path/to/repo

# Scan a git diff
uv run s0 scan path/to/repo --diff main

# Scan one file
uv run s0 scan path/to/repo/file.py --mode file

# Skip the LLM (raw scanner findings only)
uv run s0 scan path/to/repo --no-llm --format sarif --out report.sarif

# Run a harness against the labeled bench
uv run s0 eval --harness baseline_v0_agentic --all

# Inspect prior runs
uv run s0 runs list
uv run s0 runs frontier
uv run s0 runs show <run_id>

# Check that scanners are installed
uv run s0 doctor
```

## Architecture

s0-cli has **two harnesses**, in the Meta-Harness paper's sense:

- **Inner harness** = the security-scanning agent we ship and run. Lives in `src/s0_cli/harnesses/<name>.py`. Single-file, KIRA-shaped. This is what gets optimized.
- **Outer Meta-Harness loop** (Phase 1) = a coding-agent proposer that reads `runs/` (prior harnesses + scores + traces), then writes a new `harnesses/v_n.py`. The proposer's contract is in [`SKILL.md`](SKILL.md).

```
┌────────────────────┐
│  s0 scan PATH      │  ← user-facing product
└────────┬───────────┘
         ▼
   ┌──────────────────────────────────────────┐
   │ Inner harness (e.g. baseline_v0_agentic) │
   │  • env_snapshot bootstrap                │
   │  • tool loop: read_file, grep_code,      │
   │    git_blame, run_scanner, add_finding,  │
   │    mark_false_positive, task_complete    │
   │  • findings + full trace                 │
   └────────┬─────────────────────────────────┘
            ▼
   ┌──────────────────────────────────────────┐
   │ runs/<ts>__<id>/                         │
   │  harness.py, score.json, summary.md,     │
   │  traces/<task>/{prompt,response,         │
   │  tools.jsonl, observation, findings}     │
   └──────────────────────────────────────────┘
            ▲                  ▲
            │                  │
   s0 runs CLI (humans)   Phase 1 proposer
```

Three CLI entrypoints, all hitting the same inner harness:

| Command       | Role               |
| ------------- | ------------------ |
| `s0 scan`     | product            |
| `s0 eval`     | benchmark (Phase 0) |
| `s0 optimize` | outer loop (Phase 1) |

## Seed harnesses

| File                                           | Turns | Tools                             | Anchor on Pareto    |
| ---------------------------------------------- | ----- | --------------------------------- | ------------------- |
| `harnesses/baseline_v0_singleshot.py`          | 1     | `add_finding`, `task_complete`    | cost / latency      |
| `harnesses/baseline_v0_agentic.py`             | ≤30   | full investigation surface (KIRA) | accuracy            |

Two seeds give the Phase-1 proposer two real anchors (matches Meta-Harness paper §4 multi-seed initialization).

## Roadmap

- **Phase 0** (this scaffold): seed harnesses, semgrep, evaluator, run-store, mini-bench.
- **Phase 1**: outer Meta-Harness loop (`s0 optimize`).
- **Phase 2**: real scanner suite (bandit, gitleaks, trivy, ruff, npm audit).
- **Phase 3**: vibe-code LLM detectors as `Scanner` plugins.
- **Phase 4**: bench expansion + held-out test set.
- **Phase 5**: distribution (GitHub Action, pre-commit, Docker, `s0 fix`).

## How LLMs are used

| Stage                      | Detection            | Reasoning        | Decision         |
| -------------------------- | -------------------- | ---------------- | ---------------- |
| Static scan (Phase 0)      | classic scanners     | —                | —                |
| Triage (Phase 0)           | —                    | LLM (single shot or agentic) | LLM              |
| Investigation (agentic)    | —                    | LLM tool loop    | LLM              |
| Vibe-code (Phase 3)        | LLM as scanner       | LLM (same call)  | LLM              |
| Harness search (Phase 1)   | —                    | proposer LLM     | evaluator (code) |
| Fix (Phase 5)              | LLM                  | LLM              | human / CI       |

## References

- Lee et al. **Meta-Harness: End-to-End Optimization of Model Harnesses.** arXiv:2603.28052 (2026). [paper](https://arxiv.org/abs/2603.28052) · [code](https://github.com/stanford-iris-lab/meta-harness) · [tbench2 artifact](https://github.com/stanford-iris-lab/meta-harness-tbench2-artifact)
- KRAFTON AI & Ludo Robotics. **Terminus-KIRA.** [github.com/krafton-ai/KIRA](https://github.com/krafton-ai/KIRA)

## License

Apache-2.0. See [LICENSE](LICENSE).
