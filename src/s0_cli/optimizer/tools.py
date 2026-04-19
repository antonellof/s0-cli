"""Tools the proposer agent uses to navigate the run-store and produce a harness.

Read-only against everything except `src/s0_cli/harnesses/<new>.py` and
`src/s0_cli/prompts/<new>.txt`. Writes are sandboxed to those two directories
and validated again by the outer loop after the agent finishes.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from s0_cli.harness.tools import ToolCallRecord

WRITE_HARNESS_PATH_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]+$")


@dataclass
class ProposerToolContext:
    runs_dir: Path
    harnesses_dir: Path
    prompts_dir: Path
    skill_md: str
    initial_summary: str

    written_harness: Path | None = None
    written_prompt: Path | None = None
    finished: bool = False
    finish_summary: str = ""
    trace: list[ToolCallRecord] = field(default_factory=list)


PROPOSER_TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "list_runs",
            "description": "List run IDs in the run-store, newest first. Optionally only the Pareto frontier.",
            "parameters": {
                "type": "object",
                "properties": {
                    "frontier_only": {"type": "boolean", "description": "Only Pareto-frontier runs. Default false."},
                    "limit": {"type": "integer", "description": "Max runs to return. Default 20."},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_run",
            "description": "Return summary.md + score.json + config.json for one run.",
            "parameters": {
                "type": "object",
                "properties": {"run_id": {"type": "string"}},
                "required": ["run_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_harness",
            "description": "Return the source code of a prior run's harness.py snapshot, OR of a current harness file by name.",
            "parameters": {
                "type": "object",
                "properties": {
                    "run_id": {"type": "string", "description": "Either a run_id, or a harness name like 'baseline_v0_agentic'."},
                },
                "required": ["run_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_trace",
            "description": "Return the per-task trace files (observation.txt + tools.jsonl + scored.json) for a single task in a run.",
            "parameters": {
                "type": "object",
                "properties": {
                    "run_id": {"type": "string"},
                    "task_id": {"type": "string"},
                },
                "required": ["run_id", "task_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_tasks",
            "description": "List bench tasks present in a run's traces directory.",
            "parameters": {
                "type": "object",
                "properties": {"run_id": {"type": "string"}},
                "required": ["run_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_skill",
            "description": "Return the SKILL.md proposer contract.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_harness",
            "description": (
                "Write a new harness file. `name` must match `^[a-zA-Z][a-zA-Z0-9_]+$` and "
                "the file will be created at src/s0_cli/harnesses/<name>.py. The class inside "
                "must subclass Harness with name attribute equal to <name>."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "source": {"type": "string", "description": "Full Python source for the harness file."},
                },
                "required": ["name", "source"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_prompt",
            "description": "Write a prompt template at src/s0_cli/prompts/<name>.txt.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "source": {"type": "string"},
                },
                "required": ["name", "source"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "validate",
            "description": (
                "Run the static validator (syntax, forbidden imports, Harness subclass present, "
                "name attribute matches filename) on the harness file you just wrote. Call this "
                "BEFORE finish to catch obvious mistakes that would waste an evaluation budget."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finish",
            "description": (
                "Signal that the new harness is ready for evaluation. Provide a short summary "
                "of what was changed and the expected effect."
            ),
            "parameters": {
                "type": "object",
                "properties": {"summary": {"type": "string"}},
                "required": ["summary"],
            },
        },
    },
]


class ProposerTools:
    SCHEMAS = PROPOSER_TOOL_SCHEMAS

    def __init__(self, ctx: ProposerToolContext):
        self.ctx = ctx

    def dispatch(self, name: str, arguments: dict[str, Any]) -> dict[str, Any] | str:
        method = getattr(self, f"_t_{name}", None)
        if method is None:
            return {"error": f"Unknown tool: {name}"}
        try:
            return method(**arguments)
        except TypeError as e:
            return {"error": f"Bad arguments for {name}: {e}"}
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}"}

    def _t_list_runs(self, frontier_only: bool = False, limit: int = 20) -> dict[str, Any]:
        from s0_cli.optimizer.context import _load_runs, _pareto

        runs = _load_runs(self.ctx.runs_dir, limit=200)
        if frontier_only:
            runs = _pareto(runs)
        runs = runs[:limit]
        return {
            "count": len(runs),
            "runs": [
                {
                    "run_id": r.run_id,
                    "harness": r.harness_name,
                    "f1": r.f1,
                    "tokens": r.tokens,
                    "turns": r.turns,
                }
                for r in runs
            ],
        }

    def _t_read_run(self, run_id: str) -> dict[str, Any]:
        path = self._resolve_run(run_id)
        if path is None:
            return {"error": f"Run not found: {run_id}"}
        return {
            "run_id": path.name,
            "summary": _read_text(path / "summary.md"),
            "score": _read_json(path / "score.json"),
            "config": _read_json(path / "config.json"),
        }

    def _t_read_harness(self, run_id: str) -> dict[str, Any]:
        live = self.ctx.harnesses_dir / f"{run_id}.py"
        if live.is_file():
            return {"name": run_id, "source": live.read_text(encoding="utf-8"), "from": "live"}
        path = self._resolve_run(run_id)
        if path is None:
            return {"error": f"Neither a harness nor a run: {run_id}"}
        src = path / "harness.py"
        if not src.exists():
            return {"error": f"No harness.py snapshot in {run_id}"}
        return {"name": path.name, "source": src.read_text(encoding="utf-8"), "from": "run"}

    def _t_list_tasks(self, run_id: str) -> dict[str, Any]:
        path = self._resolve_run(run_id)
        if path is None:
            return {"error": f"Run not found: {run_id}"}
        traces = path / "traces"
        if not traces.exists():
            return {"tasks": []}
        return {"tasks": sorted(p.name for p in traces.iterdir() if p.is_dir())}

    def _t_read_trace(self, run_id: str, task_id: str) -> dict[str, Any]:
        path = self._resolve_run(run_id)
        if path is None:
            return {"error": f"Run not found: {run_id}"}
        tdir = path / "traces" / task_id
        if not tdir.exists():
            return {"error": f"Task not found in run: {task_id}"}
        out = {
            "run_id": path.name,
            "task_id": task_id,
            "observation": _truncate(_read_text(tdir / "observation.txt"), 8000),
            "scored": _read_json(tdir / "scored.json"),
            "ground_truth": _read_json(tdir / "ground_truth.json"),
            "findings": _read_json(tdir / "findings.json"),
        }
        tools_jsonl = tdir / "tools.jsonl"
        if tools_jsonl.exists():
            lines = tools_jsonl.read_text(encoding="utf-8").splitlines()
            out["tool_calls"] = [
                json.loads(line) for line in lines[-20:] if line.strip()
            ]
        return out

    def _t_read_skill(self) -> dict[str, Any]:
        return {"skill_md": self.ctx.skill_md}

    def _t_write_harness(self, name: str, source: str) -> dict[str, Any]:
        if not WRITE_HARNESS_PATH_RE.match(name):
            return {"error": f"Bad name {name!r}; must match ^[a-zA-Z][a-zA-Z0-9_]+$"}
        if name in {"baseline_v0_agentic", "baseline_v0_singleshot", "__init__"}:
            return {"error": f"Refusing to overwrite seed harness {name!r}; pick a new name."}
        target = self.ctx.harnesses_dir / f"{name}.py"
        target.write_text(source, encoding="utf-8")
        self.ctx.written_harness = target
        return {"ok": True, "path": str(target), "bytes": len(source)}

    def _t_write_prompt(self, name: str, source: str) -> dict[str, Any]:
        if not WRITE_HARNESS_PATH_RE.match(name):
            return {"error": f"Bad name {name!r}; must match ^[a-zA-Z][a-zA-Z0-9_]+$"}
        target = self.ctx.prompts_dir / f"{name}.txt"
        target.write_text(source, encoding="utf-8")
        self.ctx.written_prompt = target
        return {"ok": True, "path": str(target), "bytes": len(source)}

    def _t_validate(self) -> dict[str, Any]:
        from s0_cli.eval.validate import validate_harness

        if self.ctx.written_harness is None:
            return {"ok": False, "errors": ["No harness written yet."], "warnings": []}
        report = validate_harness(self.ctx.written_harness)
        return {
            "ok": report.ok,
            "errors": list(report.errors),
            "warnings": list(report.warnings),
            "harness_class": report.harness_class,
        }

    def _t_finish(self, summary: str) -> dict[str, Any]:
        self.ctx.finished = True
        self.ctx.finish_summary = summary
        return {"ok": True, "wrote_harness": str(self.ctx.written_harness) if self.ctx.written_harness else None}

    def _resolve_run(self, run_id: str) -> Path | None:
        cand = self.ctx.runs_dir / run_id
        if cand.is_dir():
            return cand
        if not self.ctx.runs_dir.exists():
            return None
        for p in self.ctx.runs_dir.iterdir():
            if p.is_dir() and (p.name == run_id or p.name.endswith(run_id) or run_id in p.name):
                return p
        return None


def _read_json(path: Path, default=None):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def _read_text(path: Path) -> str:
    if not path.exists():
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _truncate(s: str, n: int) -> str:
    if len(s) <= n:
        return s
    return s[: n - 32] + f"\n... [truncated, total {len(s)} chars]"
