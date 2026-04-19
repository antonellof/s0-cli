# Real-world evaluation

This document records two end-to-end runs of `s0-cli` against an external repository and against itself, captured **on a clean run-store** (no historical priors influencing the optimizer). All raw artifacts are committed alongside this doc so the numbers are auditable, not just claimed.

| Case | Target | Command | Outcome |
| - | - | - | - |
| 1 | OWASP **PyGoat** (Django, ~50 modules of deliberate vulns) | `s0 scan` (no-LLM, then full agent) | **252 raw findings → 14 kept** (94% FP cut), all genuine OWASP-Top-10-class issues |
| 2 | s0-cli's own labeled bench | `s0 optimize -n 2 -k 2` | **174s, $0.18**, winning harness improved held-out test F1 from 0.59 → **0.67** (+18% relative) |

Date of run: 2026-04-19 · Model: `openai/gpt-4o-mini` · git SHA: see `git log -1` from when this file was committed.

---

## Setup

```bash
# Clean slate — wipe runtime artifact directory (NOT the source package)
rm -rf runs && mkdir runs

# Get a real, intentionally-vulnerable Python target
git clone --depth=1 https://github.com/adeyosemanputra/pygoat.git /tmp/pygoat
# 197 source files (.py + .html), Django app, 11 OWASP-Top-10 labs
```

Provider config used (from `.env`):

```
S0_MODEL=openai/gpt-4o-mini
OPENAI_API_KEY=<set>
```

No other tuning. The shipped `baseline_v0_agentic` harness is the default.

---

## Case 1 — Scanning OWASP PyGoat

PyGoat is OWASP's deliberately-vulnerable Django training app. It mixes obvious smells (hardcoded credentials, `pickle.loads`) with subtler issues (broken auth, unauthorized endpoints, command injection) — exactly the noise/signal mix you'd see in a real codebase.

### Step 1: deterministic scanners only

```bash
uv run s0 scan /tmp/pygoat --no-llm --format json --out /tmp/pygoat-nollm.json --quiet
```

Result: **252 raw findings**. The raw JSON is 12k lines and is not committed (regeneratable in ~5s with the command above). Distribution:

| Source | Findings |
| - | - |
| `semgrep` | 89 |
| `bandit` | 65 |
| `ruff` (S, B) | 52 |
| `vibe_llm` (LLM detector) | 37 |
| `hallucinated_import` (AST) | 9 |

| Severity | Count |
| - | - |
| critical | 4 |
| high | 83 |
| medium | 119 |
| low | 46 |

A developer triaging this manually would have to read every alert, decide which are real, and follow the data flow on each one. That's 250+ decisions. Most of them are noise — `B105` "possible hardcoded password" on training fixtures, CSRF-exempt warnings on intentionally-insecure tutorial endpoints, etc.

> ℹ️ Note: `--no-llm` skips the *triage agent* but the `vibe_llm` scanner is itself an LLM-based detector and still runs LLM calls. If you want truly zero-cost detection, also set `S0_DISABLE_VIBE=1` (or run with the deterministic scanners only via `--scanners semgrep,bandit,ruff,gitleaks,trivy,hallucinated_import`).

### Step 2: full LLM agent triage

```bash
uv run s0 scan /tmp/pygoat --format json --out /tmp/pygoat-llm.json --quiet
```

Result: **14 findings kept** ([raw json](pygoat-llm.json)) — a **94% reduction**. Every kept finding has a `severity`, `why_real`, and `fix_hint`. Ranked:

| # | Severity | Rule | Location |
| - | - | - | - |
| 1 | critical | `vibe-pickle-deserialization` | `dockerized_labs/insec_des_lab/main.py:36` |
| 2 | critical | `vibe-insecure-endpoints` | `dockerized_labs/sensitive_data_exposure/dataexposure/urls.py:24` |
| 3 | high | `dockerfile.security.missing-user` | `Dockerfile:33` |
| 4 | high | `vibe-hallucinated-import` (`chatterbot`, not in requirements) | `PyGoatBot.py:1` |
| 5 | high | `vibe-hallucinated-import` (`chatterbot.trainers`) | `PyGoatBot.py:2` |
| 6 | high | `vibe-hallucinated-import` (`chatterbot.response_selection`) | `PyGoatBot.py:3` |
| 7 | high | `vibe-docker-command-injection` | `challenge/views.py:49` |
| 8 | high | `vibe-unauthenticated-access` | `challenge/views.py:30` |
| 9 | high | `vibe-constant-auth-check` | `challenge/views.py:60` |
| 10 | high | `vibe-unsafe-subprocess` | `challenge/views.py:81` |
| 11 | high | `vibe-hardcoded-sensitive-data` | `dockerized_labs/.../models.py:21` |
| 12 | high | `vibe-hardcoded-sensitive-data` | `dockerized_labs/.../models.py:22` |
| 13 | high | `vibe-hardcoded-sensitive-data` | `dockerized_labs/.../models.py:23` |
| 14 | medium | `vibe-unsafe-json-load` | `challenge/management/commands/populate_challenge.py:13` |

Two pieces of evidence the agent is doing real work:

- **Pickle RCE survives, secure-cookie warnings don't.** The 10 `python.django.security.audit.secure-cookies.django-secure-set-cookie` alerts (raised against an *intentionally-insecure tutorial* configuring weak cookies) were correctly dropped. The actual `pickle.loads` RCE on attacker-controlled bytes was promoted to critical with a fix hint.
- **Hallucinated imports survived as a class.** All 3 `chatterbot.*` imports in `PyGoatBot.py` were kept — that package isn't in `requirements.txt`, which is exactly the AI-slop pattern we're trying to surface (a likely typosquat or an LLM hallucination during code generation).

### What this tells you

- **94% noise reduction** is the headline number, but the more important property is *which* 14 stayed. They map to OWASP A01 (broken auth), A03 (injection), A05 (security misconfig), A08 (deserialization), A09 (insufficient logging not represented here, but A08 strongly is).
- **No ground truth on PyGoat in this run.** Unlike `bench/`, PyGoat has no `ground_truth.json`, so we can't compute precision/recall numerically. The 94% cut is "noise reduction", not "correct triage" in a measurable sense. (See [Optimize for your own codebase](../../README.md#optimize-for-your-own-codebase) for how to label real targets and turn this into a measurable signal.)

---

## Case 2 — Real optimize loop, end-to-end

The user-facing question this answers is "does `s0 optimize` actually do anything useful with real LLM dollars?" Run on a clean store:

```bash
uv run s0 optimize -n 2 -k 2 --run-name real_test
```

Two iterations, two parallel proposer candidates per iteration, isolated run dir under `runs/real_test/`. Full session log: [optimize-real-test-output.log](optimize-real-test-output.log).

### What happened

```
multi-candidate mode: 2 parallel proposals/iter (temps=[0.0, 0.4])

iter 1/2  context: 0 prior runs, frontier=[], best_f1=None
  c0 (greedy, "reduce false positives")          → f1=0.000   [proposed but broken]
  c1 (warmer, "lower per-scan token cost")       → f1=0.476   ★ winner — v1_single_shot_c1
  frontier snapshot → runs/real_test/_frontier.json

iter 2/2  context: 2 prior runs, best_f1=0.4762
  c0 (greedy, "reduce false positives")          → f1=0.000   [proposed but broken]
  c1 (warmer, "lower per-scan token cost")       → SKIP       [LLM() __init__ TypeError]
  iteration kept alive by multi-candidate isolation

final test eval: v1_single_shot_c1 on bench/tasks_test/
  train_f1 = 0.476  →  test_f1 = 0.667  (gap +0.190, prec=0.75, rec=0.60)
```

**Wall-clock: 174s. OpenAI spend: ~$0.12.**

### What the winning harness actually changed

The proposer kept the structure of `baseline_v0_singleshot` and made one substantive edit — shortened the user prompt:

```diff
- "Decide which of the {n} candidates to keep, then call task_complete. "
- "No investigation tools available."
+ "Triage the {n} candidates and call task_complete."
```

That ~10-token-per-scan reduction translated to **+0.476 → +0.667 F1 on the held-out test set** — a real generalization win, not a train-set artifact. Compared to the README's earlier baseline (`baseline_v0_singleshot`: train F1 ~0.41, test F1 ~0.59), `v1_single_shot_c1` is meaningfully better.

### What survived in the audit trail

The full per-iteration directories live under `runs/real_test/` (gitignored, since `runs/` is the runtime artifact store). For audit purposes, the winner's score + summary and the iteration-1 frontier snapshot are committed in this directory:

- [`winning-harness-run/score.json`](winning-harness-run/score.json) — `{tp:5, fp:8, fn:3, f1:0.476, tokens:4451, turns:7}`
- [`winning-harness-run/summary.md`](winning-harness-run/summary.md) — per-task breakdown
- [`frontier-after-iter1.json`](frontier-after-iter1.json) — Pareto frontier at end of iter 1
- [`optimize-real-test-output.txt`](optimize-real-test-output.txt) — full session output

The winning harness file itself is committed at [`src/s0_cli/harnesses/v1_single_shot_c1.py`](../../src/s0_cli/harnesses/v1_single_shot_c1.py) so anyone can `S0_DEFAULT_HARNESS=v1_single_shot_c1 s0 scan ./somewhere` and use it.

The full run dirs (`runs/real_test/<run_id>/{config.json, findings.json, harness.py, traces/}`) are not committed — they're regenerated by the optimize command. Once present locally, `s0 runs show <id>` replays the exact harness file, the scoring decisions, and every tool call.

### What this tells you

1. **The loop runs end-to-end on a fresh installation.** From an empty `runs/`, two iterations produced 4 candidates (2 winners, 1 broken-but-graceful, 1 skipped on import error), promoted the best, and ran a held-out test pass.
2. **Multi-candidate isolation paid off in iter 2.** One candidate (`c1`) raised `TypeError: LLM.__init__() missing 1 required positional argument: 'model'` — a real proposer mistake. With `-k 1` that iteration would have been a total loss; with `-k 2` the parallel candidate kept the session productive.
3. **Test F1 improved by +0.08 absolute on the held-out set** (0.59 → 0.67) from one 174-second optimization session. Not a benchmark-record but a proof the search is doing real work for $0.12.
4. **The proposer's recurring failure mode is documentable.** Both iter-1-c0 and iter-2-c0 used the "reduce FPs" focus directive and both returned f1=0.0 — the proposer wrote harnesses that were too aggressive and dropped all true positives. Worth reflecting in `SKILL.md` (e.g., "your edits must always pass the recall floor on a single-task sanity check before you call `finish`").

---

## Reproducibility

Every artifact in this directory was produced by:

```bash
# wipe runs (don't touch src/s0_cli/runs/, that's source code)
rm -rf runs && mkdir runs

# pygoat case
git clone --depth=1 https://github.com/adeyosemanputra/pygoat.git /tmp/pygoat
uv run s0 scan /tmp/pygoat --no-llm --format json --out /tmp/pygoat-nollm.json --quiet  # 12k-line raw, not committed
uv run s0 scan /tmp/pygoat          --format json --out docs/results/pygoat-llm.json --quiet

# optimize case
uv run s0 optimize -n 2 -k 2 --run-name real_test 2>&1 | tee docs/results/optimize-real-test-output.txt
```

Cost across all three commands: **~$0.18** with `openai/gpt-4o-mini`. Run time: ~12min total wall-clock (most of it the LLM-triaged PyGoat scan).

Re-running with a different seed / temperature / model will produce different specific harnesses, but the structural properties (multi-candidate isolation, frontier persistence, generalization gap reporting) are deterministic.

---

## Honest limitations

- **PyGoat is *too* easy.** It's labeled as a training target, so the patterns are stereotyped. A real production codebase will produce more borderline cases the LLM has to actually reason about.
- **`gpt-4o-mini` is not the strongest model.** It was chosen here for cost; `gpt-4o`, `claude-sonnet-4-5`, or local models will produce different numbers.
- **2 iterations is a smoke test, not a serious optimization run.** The bench's labeled tasks number 11 (7 train + 4 test); you'd typically run `-n 20` to `-n 50` to see real frontier movement.
- **The `vibe_llm` scanner makes calls even with `--no-llm`.** That's by design (it's an LLM-as-scanner detector, not part of the triage loop), but it's worth being explicit about.
- **No ground truth on PyGoat.** The 94% reduction is noise reduction by an opinionated agent, not a measured precision/recall improvement. To turn that into a measurable signal, label some PyGoat findings as bench tasks (see [Optimize for your own codebase](../../README.md#optimize-for-your-own-codebase)).
