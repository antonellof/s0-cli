"""Run-store reader/writer.

The optimizer's proposer agent and the human-facing `s0 runs` CLI both read
from this module. Keep the schema stable; add fields, don't rename.
"""

from __future__ import annotations

import dataclasses
import inspect
import json
import secrets
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from s0_cli.harness.base import Harness, ScanResult
from s0_cli.scanners.base import Finding


@dataclass
class TaskTrace:
    task_id: str
    findings: list[Finding] = field(default_factory=list)
    trace: list[dict[str, Any]] = field(default_factory=list)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    usage: dict[str, Any] = field(default_factory=dict)
    ended_via: str = "task_complete"
    ground_truth: list[dict[str, Any]] | None = None
    scored: dict[str, Any] | None = None


@dataclass
class RunRecord:
    run_id: str
    created_at: str
    harness_name: str
    target_label: str
    invocation: str
    config: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    score: dict[str, Any] | None = None
    summary: str = ""
    tasks: list[TaskTrace] = field(default_factory=list)


class RunStore:
    """Filesystem-backed run store."""

    def __init__(self, root: Path):
        self.root = Path(root)

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)

    def new_run_dir(self, harness_name: str) -> tuple[Path, str]:
        ts = datetime.now(UTC).strftime("%Y-%m-%dT%H-%M-%SZ")
        sid = secrets.token_hex(2)
        run_id = f"{ts}__{harness_name}__{sid}"
        path = self.root / run_id
        path.mkdir(parents=True, exist_ok=True)
        (path / "traces").mkdir(exist_ok=True)
        return path, run_id

    def list_runs(self) -> list[Path]:
        if not self.root.exists():
            return []
        return sorted(
            (p for p in self.root.iterdir() if p.is_dir()),
            key=lambda p: p.name,
            reverse=True,
        )

    def read_run(self, run_id: str) -> RunRecord | None:
        path = self.find(run_id)
        if path is None:
            return None
        return _load_run(path)

    def find(self, run_id: str) -> Path | None:
        cand = self.root / run_id
        if cand.is_dir():
            return cand
        for p in self.list_runs():
            if p.name.endswith(run_id) or run_id in p.name:
                return p
        return None


def write_run(
    *,
    store: RunStore,
    harness: Harness,
    target_label: str,
    invocation: str,
    config: dict[str, Any],
    result: ScanResult,
    score: dict[str, Any] | None = None,
    task_traces: Iterable[TaskTrace] | None = None,
) -> tuple[Path, str]:
    """Persist a single run to the store."""
    store.ensure()
    path, run_id = store.new_run_dir(harness.name or harness.__class__.__name__)

    _snapshot_harness_source(harness, path / "harness.py")

    (path / "config.json").write_text(
        json.dumps(_safe(config), indent=2, default=str), encoding="utf-8"
    )

    findings_payload = [f.to_dict() for f in result.findings]
    (path / "findings.json").write_text(
        json.dumps(findings_payload, indent=2, default=str), encoding="utf-8"
    )

    if score is not None:
        (path / "score.json").write_text(
            json.dumps(_safe(score), indent=2, default=str), encoding="utf-8"
        )

    if task_traces:
        traces_dir = path / "traces"
        for t in task_traces:
            tdir = traces_dir / _safe_id(t.task_id)
            tdir.mkdir(exist_ok=True)
            (tdir / "findings.json").write_text(
                json.dumps([f.to_dict() for f in t.findings], indent=2, default=str),
                encoding="utf-8",
            )
            (tdir / "tools.jsonl").write_text(
                "\n".join(json.dumps(c, default=str) for c in t.tool_calls),
                encoding="utf-8",
            )
            (tdir / "observation.txt").write_text(
                _format_trace(t.trace), encoding="utf-8"
            )
            if t.ground_truth is not None:
                (tdir / "ground_truth.json").write_text(
                    json.dumps(t.ground_truth, indent=2, default=str), encoding="utf-8"
                )
            if t.scored is not None:
                (tdir / "scored.json").write_text(
                    json.dumps(_safe(t.scored), indent=2, default=str), encoding="utf-8"
                )

    summary = _build_summary(
        run_id=run_id,
        harness=harness,
        target_label=target_label,
        invocation=invocation,
        result=result,
        score=score,
        config=config,
    )
    (path / "summary.md").write_text(summary, encoding="utf-8")

    return path, run_id


def _snapshot_harness_source(harness: Harness, dest: Path) -> None:
    """Best-effort snapshot of the harness file the proposer / user wrote.

    Tries (in order):
      1. inspect.getsource(module) — works for normally-imported harnesses.
      2. inspect.getsource(type(harness)) — fallback if the module has no
         retrievable source but the class does.
      3. Read `module.__file__` directly — works for harnesses loaded via
         `importlib.util.spec_from_file_location` (which is how `s0 optimize`
         loads candidate harnesses, and where `inspect.getfile` raises
         TypeError on Python 3.14+ with a "built-in class" message).

    A failed snapshot must NOT abort the eval; we keep evaluations going so
    optimize-loop iterations always produce a logged outcome.
    """
    src: str | None = None
    cls = type(harness)
    module = inspect.getmodule(cls)

    if module is not None:
        try:
            src = inspect.getsource(module)
        except (OSError, TypeError):
            src = None

    if src is None:
        try:
            src = inspect.getsource(cls)
        except (OSError, TypeError):
            src = None

    if src is None and module is not None:
        mod_file = getattr(module, "__file__", None)
        if mod_file:
            try:
                src = Path(mod_file).read_text(encoding="utf-8")
            except OSError:
                src = None

    if src is None:
        src = (
            "# (source unavailable: harness loaded dynamically and inspect "
            "could not retrieve source)\n"
        )

    dest.write_text(src, encoding="utf-8")


def _format_trace(trace: list[dict[str, Any]]) -> str:
    lines = []
    for ev in trace:
        kind = ev.get("type", "?")
        turn = ev.get("turn", "")
        if kind == "llm_call":
            tcs = ev.get("tool_calls", [])
            tc_str = ", ".join(t["name"] for t in tcs) or "(content only)"
            lines.append(
                f"[turn {turn}] llm: in={ev.get('input_tokens')} out={ev.get('output_tokens')} "
                f"cached={ev.get('cached_input_tokens')} {ev.get('duration_ms')}ms tools={tc_str}"
            )
            preview = (ev.get("content_preview") or "").strip()
            if preview:
                lines.append(f"           content: {preview}")
        elif kind == "summarize":
            lines.append(f"[turn {turn}] context overflow -> summarized history")
        elif kind == "error":
            lines.append(f"[turn {turn}] ERROR: {ev.get('error')}")
        else:
            lines.append(f"[turn {turn}] {kind}: {ev}")
    return "\n".join(lines)


def _build_summary(
    *,
    run_id: str,
    harness: Harness,
    target_label: str,
    invocation: str,
    result: ScanResult,
    score: dict[str, Any] | None,
    config: dict[str, Any],
) -> str:
    by_sev: dict[str, int] = {}
    for f in result.findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    sev_str = ", ".join(f"{k}:{v}" for k, v in sorted(by_sev.items())) or "none"
    parts = [
        f"# Run {run_id}",
        f"- harness: `{harness.name or type(harness).__name__}`",
        f"- target: `{target_label}`",
        f"- invocation: `{invocation}`",
        f"- model: `{config.get('model', '?')}`",
        f"- ended_via: `{result.ended_via}`",
        f"- findings: {len(result.findings)} ({sev_str})",
        f"- usage: {result.usage}",
    ]
    if score is not None:
        parts.append("")
        parts.append("## Score")
        parts.append("```json")
        parts.append(json.dumps(_safe(score), indent=2, default=str))
        parts.append("```")
    if harness.description:
        parts.append("")
        parts.append(f"_Harness:_ {harness.description}")
    return "\n".join(parts) + "\n"


def _safe(d: Any) -> Any:
    if dataclasses.is_dataclass(d):
        return dataclasses.asdict(d)
    if isinstance(d, dict):
        return {str(k): _safe(v) for k, v in d.items()}
    if isinstance(d, (list, tuple)):
        return [_safe(x) for x in d]
    if isinstance(d, Path):
        return str(d)
    return d


def _safe_id(s: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)


def _load_run(path: Path) -> RunRecord:
    config = _read_json(path / "config.json", default={})
    findings_raw = _read_json(path / "findings.json", default=[])
    score = _read_json(path / "score.json", default=None)
    summary = (path / "summary.md").read_text(encoding="utf-8") if (path / "summary.md").exists() else ""

    findings = [_finding_from_dict(d) for d in findings_raw]

    tasks: list[TaskTrace] = []
    traces_dir = path / "traces"
    if traces_dir.exists():
        for tdir in sorted(traces_dir.iterdir()):
            if not tdir.is_dir():
                continue
            t_findings = [
                _finding_from_dict(d) for d in _read_json(tdir / "findings.json", default=[])
            ]
            tcs = []
            tcs_path = tdir / "tools.jsonl"
            if tcs_path.exists():
                for line in tcs_path.read_text(encoding="utf-8").splitlines():
                    if not line.strip():
                        continue
                    try:
                        tcs.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            tasks.append(
                TaskTrace(
                    task_id=tdir.name,
                    findings=t_findings,
                    tool_calls=tcs,
                    ground_truth=_read_json(tdir / "ground_truth.json", default=None),
                    scored=_read_json(tdir / "scored.json", default=None),
                )
            )

    return RunRecord(
        run_id=path.name,
        created_at=path.name.split("__")[0],
        harness_name=config.get("harness_name") or "?",
        target_label=config.get("target_label") or "?",
        invocation=config.get("invocation") or "?",
        config=config,
        findings=findings,
        score=score,
        summary=summary,
        tasks=tasks,
    )


def _read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def _finding_from_dict(d: dict[str, Any]) -> Finding:
    return Finding(
        rule_id=d.get("rule_id", "?"),
        severity=d.get("severity", "medium"),
        path=d.get("path", "?"),
        line=int(d.get("line", 0)),
        end_line=d.get("end_line"),
        message=d.get("message", ""),
        source=d.get("source", "?"),
        cwe=tuple(d.get("cwe", []) or ()),
        snippet=d.get("snippet"),
        confidence=float(d.get("confidence", 1.0)),
        fix_hint=d.get("fix_hint"),
        why_real=d.get("why_real"),
        false_positive=bool(d.get("false_positive", False)),
        raw=d.get("raw", {}) or {},
    )
