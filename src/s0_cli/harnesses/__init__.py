"""Inner harnesses.

One file per candidate scanning agent. The outer Meta-Harness loop
(`s0 optimize`) writes new files here as it explores the design space.

Two seed harnesses ship by default:

- `baseline_v0_singleshot` — Pareto cost anchor (1 turn)
- `baseline_v0_agentic`    — Pareto accuracy anchor (KIRA-shaped, ≤30 turns)
"""
