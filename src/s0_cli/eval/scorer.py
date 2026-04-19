"""Match findings to ground-truth labels and compute metrics.

Matching policy: a predicted finding matches a ground-truth label if the
file path matches AND the predicted line is within `[gt.line - tol, gt.line + tol]`
(default tol = 5). The first unmatched ground-truth label that satisfies the
constraint is consumed (greedy 1:1 matching, ordered by severity then line).

Metrics:
- precision = TP / (TP + FP)
- recall = TP / (TP + FN)
- f1 = harmonic mean
- f1_weighted = severity-weighted F1 (critical=4, high=3, medium=2, low=1)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePath
from typing import Any

from s0_cli.config import SEVERITY_RANK
from s0_cli.scanners.base import Finding

_SEV_WEIGHT = {"info": 0.5, "low": 1.0, "medium": 2.0, "high": 3.0, "critical": 4.0}


@dataclass
class MatchResult:
    true_positives: list[tuple[Finding, dict[str, Any]]] = field(default_factory=list)
    false_positives: list[Finding] = field(default_factory=list)
    false_negatives: list[dict[str, Any]] = field(default_factory=list)
    severity_diffs: list[tuple[str, str]] = field(default_factory=list)


def score_findings(
    predicted: list[Finding],
    ground_truth: list[dict[str, Any]],
    line_tolerance: int = 5,
) -> dict[str, Any]:
    """Compute metrics for a single labeled task."""
    match = _match(predicted, ground_truth, line_tolerance)

    tp = len(match.true_positives)
    fp = len(match.false_positives)
    fn = len(match.false_negatives)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    w_tp = sum(_SEV_WEIGHT.get(gt.get("severity", "medium"), 1.0) for _, gt in match.true_positives)
    w_fp = sum(_SEV_WEIGHT.get(p.severity, 1.0) for p in match.false_positives)
    w_fn = sum(_SEV_WEIGHT.get(gt.get("severity", "medium"), 1.0) for gt in match.false_negatives)
    w_prec = w_tp / (w_tp + w_fp) if (w_tp + w_fp) > 0 else 0.0
    w_rec = w_tp / (w_tp + w_fn) if (w_tp + w_fn) > 0 else 0.0
    w_f1 = (2 * w_prec * w_rec / (w_prec + w_rec)) if (w_prec + w_rec) > 0 else 0.0

    sev_correct = sum(
        1 for p, gt in match.true_positives if p.severity == gt.get("severity")
    )
    sev_off_by = [
        SEVERITY_RANK.get(p.severity, 2) - SEVERITY_RANK.get(gt.get("severity", "medium"), 2)
        for p, gt in match.true_positives
    ]

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "weighted_precision": round(w_prec, 4),
        "weighted_recall": round(w_rec, 4),
        "weighted_f1": round(w_f1, 4),
        "severity_correct": sev_correct,
        "severity_off_by_mean": (sum(abs(x) for x in sev_off_by) / len(sev_off_by)) if sev_off_by else 0.0,
        "matches": [
            {
                "predicted": {"rule_id": p.rule_id, "path": p.path, "line": p.line, "severity": p.severity},
                "ground_truth": gt,
            }
            for p, gt in match.true_positives
        ],
        "false_positives": [
            {"rule_id": p.rule_id, "path": p.path, "line": p.line, "severity": p.severity, "source": p.source}
            for p in match.false_positives
        ],
        "false_negatives": match.false_negatives,
    }


def _match(
    predicted: list[Finding],
    ground_truth: list[dict[str, Any]],
    line_tolerance: int,
) -> MatchResult:
    res = MatchResult()
    remaining_gt = list(ground_truth)
    consumed = [False] * len(remaining_gt)

    sorted_pred = sorted(
        predicted,
        key=lambda f: (-SEVERITY_RANK.get(f.severity, 2), f.path, f.line),
    )

    for p in sorted_pred:
        idx = _find_match(p, remaining_gt, consumed, line_tolerance)
        if idx is not None:
            consumed[idx] = True
            res.true_positives.append((p, remaining_gt[idx]))
            if p.severity != remaining_gt[idx].get("severity"):
                res.severity_diffs.append((p.severity, remaining_gt[idx].get("severity", "?")))
        else:
            res.false_positives.append(p)

    for i, gt in enumerate(remaining_gt):
        if not consumed[i]:
            res.false_negatives.append(gt)

    return res


def _find_match(
    p: Finding,
    gts: list[dict[str, Any]],
    consumed: list[bool],
    tol: int,
) -> int | None:
    p_norm = _norm_path(p.path)
    candidates: list[tuple[int, int]] = []
    for i, gt in enumerate(gts):
        if consumed[i]:
            continue
        if _norm_path(gt.get("path", "")) != p_norm:
            continue
        gt_line = int(gt.get("line", 0))
        if abs(gt_line - p.line) > tol:
            continue
        candidates.append((abs(gt_line - p.line), i))
    if not candidates:
        return None
    candidates.sort()
    return candidates[0][1]


def _norm_path(p: str) -> str:
    return str(PurePath(p)).replace("\\", "/").lstrip("./")
