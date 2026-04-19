"""Bench evaluator: run a harness over labeled tasks, score findings."""

from s0_cli.eval.runner import EvalRunner, EvalSummary
from s0_cli.eval.scorer import score_findings
from s0_cli.eval.validate import validate_harness

__all__ = ["EvalRunner", "EvalSummary", "score_findings", "validate_harness"]
