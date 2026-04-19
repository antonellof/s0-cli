"""Inner harnesses.

One file per candidate harness. Phase 1's outer Meta-Harness loop will write
new files here. Two seeds ship in Phase 0:

- `baseline_v0_singleshot` — Pareto cost anchor (1 turn)
- `baseline_v0_agentic`    — Pareto accuracy anchor (KIRA-shaped, ≤30 turns)
"""
