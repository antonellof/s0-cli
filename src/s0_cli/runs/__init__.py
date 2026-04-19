"""Run store: filesystem-based archive of every scan/eval invocation.

Layout (paper §D recommends grep-friendly, hierarchical, JSONL):

    runs/<iso_ts>__<harness>__<short_id>/
      harness.py              snapshot of the harness file used
      prompt_template.txt     snapshot of the prompt (if external)
      config.json             model, settings, scanner toggles
      score.json              for eval runs only; aggregate metrics
      summary.md              human-readable one-pager
      findings.json           final reported findings
      traces/<task_id>/
        prompt.txt
        response.txt
        tools.jsonl
        observation.txt
        findings.json
        ground_truth.json     (eval only)
        scored.json           (eval only, per-task scoring)
"""

from __future__ import annotations

from s0_cli.runs.store import RunStore, write_run

__all__ = ["RunStore", "write_run"]
