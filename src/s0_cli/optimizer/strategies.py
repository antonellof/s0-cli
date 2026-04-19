"""Candidate-strategy ladder for multi-candidate proposals.

Each outer-loop iteration can fan out N parallel proposals. We don't get
diversity for free just by re-sampling the same prompt at the same
temperature — the LLM tends to converge on the same hypothesis. So each
candidate is parameterized by three knobs:

1. **Temperature** — exploit (0.0) vs. explore (>0.4).
2. **Seed hint** — which existing harness the proposer is told to extend
   (`baseline_v0_agentic`, `baseline_v0_singleshot`, or "the current best
   frontier harness"). This biases the structural starting point.
3. **Focus** — a one-line directive about what to optimize ("reduce false
   positives", "improve recall on missed CWEs", "shrink token cost while
   holding F1", etc.). This biases which failure mode the proposer attacks.

The ladder is deterministic and reproducible: ``build_strategies(n)`` always
returns the same N strategies, so a re-run of ``s0 optimize --candidates 3``
hits the same three design-space regions (modulo LLM stochasticity inside
each call). Cost scales linearly: total ≈ N × (proposer cost + eval cost),
so the user picks N as a function of their budget.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CandidateStrategy:
    """One point in the proposer's design space."""

    slot: int
    temperature: float
    seed_hint: str
    focus: str

    @property
    def label(self) -> str:
        """Short identifier used in run names + log lines."""
        return f"c{self.slot}"

    def directive(self) -> str:
        """Prompt addendum that orients the proposer toward this slot.

        Inserted near the top of the user message so it dominates the
        proposer's planning step. The seed hint is advisory ("start from"),
        not enforced — the proposer can still read other harnesses.
        """
        return (
            f"## This iteration's design slot ({self.label})\n"
            f"- **Focus**: {self.focus}\n"
            f"- **Start from**: read `{self.seed_hint}` first via `read_harness`, "
            f"then make a small additive change targeting the focus above.\n"
            f"- **Naming**: pick a unique filename. Suggested suffix: "
            f"`_{self.label}` to avoid collisions with sibling candidates "
            f"in the same iteration (e.g. `v1_xss_filter_{self.label}`).\n"
        )


_LADDER: list[CandidateStrategy] = [
    CandidateStrategy(
        slot=0,
        temperature=0.0,
        seed_hint="baseline_v0_agentic",
        focus="reduce false positives without losing any true positives",
    ),
    CandidateStrategy(
        slot=1,
        temperature=0.4,
        seed_hint="baseline_v0_singleshot",
        focus="lower per-scan token cost while holding F1 within -0.05",
    ),
    CandidateStrategy(
        slot=2,
        temperature=0.7,
        seed_hint="baseline_v0_agentic",
        focus="catch the false negatives that the current frontier misses",
    ),
    CandidateStrategy(
        slot=3,
        temperature=0.3,
        seed_hint="baseline_v0_agentic",
        focus="add or refine a vibe-code pattern (intent-level bugs the SAST tools miss)",
    ),
    CandidateStrategy(
        slot=4,
        temperature=0.5,
        seed_hint="baseline_v0_singleshot",
        focus="tighten dedup/severity-recalibration of cross-tool duplicates",
    ),
]


def build_strategies(n: int) -> list[CandidateStrategy]:
    """Return ``n`` reproducible strategies from the ladder.

    For ``n`` larger than the built-in ladder we cycle, bumping the slot
    index so harness-name collisions don't silently overwrite.
    """
    if n < 1:
        raise ValueError(f"n must be >= 1, got {n}")
    out: list[CandidateStrategy] = []
    for i in range(n):
        base = _LADDER[i % len(_LADDER)]
        if i < len(_LADDER):
            out.append(base)
        else:
            out.append(
                CandidateStrategy(
                    slot=i,
                    temperature=base.temperature,
                    seed_hint=base.seed_hint,
                    focus=base.focus,
                )
            )
    return out
