"""The fixed tool surface that inner harnesses dispatch through.

Two reasons this layer is centralized rather than inlined into each harness:

1. The Phase-1 outer loop (Meta-Harness proposer) needs a bounded action
   space to search over. If every harness can spawn arbitrary subprocesses,
   the search is unsafe and irreproducible.
2. Every tool call is recorded into the trace by the agent loop, which
   gives the proposer high-quality diagnostic data (paper Table 3).

Tools are READ-ONLY against the target. Adding a write tool requires a
separate review path (Phase 5: `s0 fix`).
"""

from __future__ import annotations

import dataclasses
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from s0_cli.scanners import REGISTRY as SCANNER_REGISTRY
from s0_cli.scanners.base import Finding
from s0_cli.targets.base import Target


@dataclass
class ToolCallRecord:
    name: str
    arguments: dict[str, Any]
    result: dict[str, Any] | str
    error: str | None = None
    duration_ms: int = 0


@dataclass
class ToolContext:
    target: Target
    output_cap_bytes: int = 30_000
    findings: list[Finding] = field(default_factory=list)
    suppressed: list[str] = field(default_factory=list)
    trace: list[ToolCallRecord] = field(default_factory=list)
    completed: bool = False
    completion_reason: str | None = None


READ_FILE_DESC = (
    "Read up to 400 lines of a file in the target. Use to inspect code "
    "around a finding. Paths must be inside the target root."
)
GREP_CODE_DESC = (
    "ripgrep across the target. Pass a regex and an optional file glob. "
    "Use to trace tainted variables, locate route handlers, etc."
)
LIST_FILES_DESC = (
    "List files under a directory of the target (recursive, capped at 200 entries)."
)
GIT_BLAME_DESC = (
    "Show `git blame` for a line range. Useful to identify when a finding was "
    "introduced and by which commit. Returns an empty result if not a git repo."
)
RUN_SCANNER_DESC = (
    "Run a registered scanner against the target and return its findings. "
    "Available scanners are listed in the system prompt."
)
ADD_FINDING_DESC = (
    "Promote a finding to the final report. Provide all fields explicitly; "
    "the harness should have already inspected evidence before calling this."
)
MARK_FALSE_POSITIVE_DESC = (
    "Suppress a finding by fingerprint with a one-line reason. Used to dedup "
    "or to filter out non-exploitable findings."
)
TASK_COMPLETE_DESC = (
    "Signal that triage is complete. Always call this last, even when you "
    "decided everything is a false positive."
)

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": READ_FILE_DESC,
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Workspace-relative or absolute path."},
                    "start_line": {"type": "integer", "description": "1-indexed; defaults to 1."},
                    "end_line": {"type": "integer", "description": "1-indexed inclusive; defaults to start+400."},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "grep_code",
            "description": GREP_CODE_DESC,
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Regex (POSIX-extended, ripgrep syntax)."},
                    "glob": {"type": "string", "description": "Optional file glob, e.g. '*.py'."},
                    "max_matches": {"type": "integer", "description": "Cap on returned matches (default 100)."},
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_files",
            "description": LIST_FILES_DESC,
            "parameters": {
                "type": "object",
                "properties": {
                    "subpath": {"type": "string", "description": "Workspace-relative subdirectory (default '.')."},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "git_blame",
            "description": GIT_BLAME_DESC,
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "start_line": {"type": "integer"},
                    "end_line": {"type": "integer"},
                },
                "required": ["path", "start_line", "end_line"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_scanner",
            "description": RUN_SCANNER_DESC,
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Scanner name (e.g. 'semgrep')."},
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add_finding",
            "description": ADD_FINDING_DESC,
            "parameters": {
                "type": "object",
                "properties": {
                    "rule_id": {"type": "string"},
                    "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                    "path": {"type": "string"},
                    "line": {"type": "integer"},
                    "end_line": {"type": "integer"},
                    "message": {"type": "string"},
                    "cwe": {"type": "array", "items": {"type": "string"}},
                    "snippet": {"type": "string"},
                    "confidence": {"type": "number", "description": "0.0-1.0"},
                    "fix_hint": {"type": "string"},
                    "why_real": {"type": "string"},
                    "source": {"type": "string", "description": "Originating scanner or 'llm:<reason>'."},
                },
                "required": ["rule_id", "severity", "path", "line", "message", "source"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "mark_false_positive",
            "description": MARK_FALSE_POSITIVE_DESC,
            "parameters": {
                "type": "object",
                "properties": {
                    "fingerprint": {"type": "string"},
                    "reason": {"type": "string"},
                },
                "required": ["fingerprint", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "task_complete",
            "description": TASK_COMPLETE_DESC,
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
]


_SINGLESHOT_SCHEMAS = [
    s for s in TOOL_SCHEMAS if s["function"]["name"] in {"add_finding", "task_complete"}
]


class Tools:
    """Dispatcher. Construct once per scan; pass to `agent_loop`."""

    SCHEMAS = TOOL_SCHEMAS
    SINGLESHOT_SCHEMAS = _SINGLESHOT_SCHEMAS

    def __init__(self, ctx: ToolContext):
        self.ctx = ctx

    @classmethod
    def schemas_for(cls, names: list[str] | None = None) -> list[dict[str, Any]]:
        if names is None:
            return cls.SCHEMAS
        wanted = set(names)
        return [s for s in cls.SCHEMAS if s["function"]["name"] in wanted]

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

    def _resolve(self, path: str) -> Path:
        p = Path(path)
        if not p.is_absolute():
            p = (self.ctx.target.root / p).resolve()
        else:
            p = p.resolve()
        try:
            p.relative_to(self.ctx.target.root.resolve())
        except ValueError as e:
            raise ValueError(f"Path escapes target root: {path}") from e
        return p

    def _cap(self, text: str) -> str:
        cap = self.ctx.output_cap_bytes
        if len(text.encode("utf-8", errors="replace")) <= cap:
            return text
        truncated = text.encode("utf-8", errors="replace")[: cap - 64].decode(
            "utf-8", errors="replace"
        )
        return truncated + f"\n... [truncated, output exceeded {cap} bytes]"

    def _t_read_file(
        self, path: str, start_line: int = 1, end_line: int | None = None
    ) -> dict[str, Any]:
        p = self._resolve(path)
        if not p.exists() or not p.is_file():
            return {"error": f"Not a file: {path}"}
        if end_line is None:
            end_line = start_line + 400
        try:
            with p.open("r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError as e:
            return {"error": str(e)}
        snippet = lines[max(0, start_line - 1) : end_line]
        text = "".join(snippet)
        return {
            "path": str(p.relative_to(self.ctx.target.root.resolve())),
            "start_line": start_line,
            "end_line": min(end_line, len(lines)),
            "total_lines": len(lines),
            "content": self._cap(text),
        }

    def _t_grep_code(
        self, pattern: str, glob: str | None = None, max_matches: int = 100
    ) -> dict[str, Any]:
        cmd = ["rg", "--line-number", "--no-heading", "--max-count", str(max_matches)]
        if glob:
            cmd += ["--glob", glob]
        cmd += ["-e", pattern, "."]
        try:
            out = subprocess.run(
                cmd,
                cwd=self.ctx.target.root,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except FileNotFoundError:
            return self._grep_fallback(pattern, glob, max_matches)
        except subprocess.TimeoutExpired:
            return {"error": "grep_code timed out"}
        if out.returncode not in (0, 1):
            return {"error": out.stderr.strip() or "ripgrep failed"}
        text = self._cap(out.stdout)
        matches = [line for line in text.splitlines() if line.strip()]
        return {"pattern": pattern, "matches": matches[:max_matches], "raw": text}

    def _grep_fallback(
        self, pattern: str, glob: str | None, max_matches: int
    ) -> dict[str, Any]:
        regex = re.compile(pattern)
        matches: list[str] = []
        for p in self.ctx.target.root.rglob(glob or "*"):
            if not p.is_file():
                continue
            if any(part.startswith(".") for part in p.parts):
                continue
            try:
                with p.open("r", encoding="utf-8", errors="replace") as f:
                    for i, line in enumerate(f, 1):
                        if regex.search(line):
                            rel = p.relative_to(self.ctx.target.root)
                            matches.append(f"{rel}:{i}:{line.rstrip()}")
                            if len(matches) >= max_matches:
                                return {"pattern": pattern, "matches": matches}
            except OSError:
                continue
        return {"pattern": pattern, "matches": matches}

    def _t_list_files(self, subpath: str = ".") -> dict[str, Any]:
        p = self._resolve(subpath)
        if not p.is_dir():
            return {"error": f"Not a directory: {subpath}"}
        entries: list[str] = []
        for sub in sorted(p.rglob("*")):
            if any(part.startswith(".") for part in sub.parts):
                continue
            if "__pycache__" in sub.parts or "node_modules" in sub.parts:
                continue
            try:
                rel = sub.relative_to(self.ctx.target.root)
            except ValueError:
                continue
            entries.append(str(rel) + ("/" if sub.is_dir() else ""))
            if len(entries) >= 200:
                entries.append("... [truncated at 200 entries]")
                break
        return {"subpath": subpath, "entries": entries}

    def _t_git_blame(
        self, path: str, start_line: int, end_line: int
    ) -> dict[str, Any]:
        p = self._resolve(path)
        if not (self.ctx.target.root / ".git").exists():
            return {"path": path, "blame": "", "note": "not a git repo"}
        try:
            out = subprocess.run(
                [
                    "git",
                    "blame",
                    "-L",
                    f"{start_line},{end_line}",
                    "--",
                    str(p.relative_to(self.ctx.target.root.resolve())),
                ],
                cwd=self.ctx.target.root,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return {"error": str(e)}
        if out.returncode != 0:
            return {"error": out.stderr.strip() or "git blame failed"}
        return {"path": path, "blame": self._cap(out.stdout)}

    def _t_run_scanner(self, name: str) -> dict[str, Any]:
        if name not in SCANNER_REGISTRY:
            return {"error": f"Unknown scanner: {name}. Available: {sorted(SCANNER_REGISTRY)}"}
        scanner = SCANNER_REGISTRY[name]()
        if not scanner.is_available():
            return {"error": f"Scanner {name!r} is not installed; check `s0 doctor`."}
        try:
            findings = scanner.run(self.ctx.target)
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}"}
        out = {
            "scanner": name,
            "count": len(findings),
            "findings": [_finding_summary(f) for f in findings[:50]],
        }
        if len(findings) > 50:
            out["truncated"] = True
            out["total"] = len(findings)
        return out

    def _t_add_finding(
        self,
        rule_id: str,
        severity: str,
        path: str,
        line: int,
        message: str,
        source: str,
        end_line: int | None = None,
        cwe: list[str] | None = None,
        snippet: str | None = None,
        confidence: float = 1.0,
        fix_hint: str | None = None,
        why_real: str | None = None,
    ) -> dict[str, Any]:
        finding = Finding(
            rule_id=rule_id,
            severity=severity,  # type: ignore[arg-type]
            path=path,
            line=int(line),
            end_line=end_line,
            message=message,
            source=source,
            cwe=tuple(cwe or ()),
            snippet=snippet,
            confidence=float(confidence),
            fix_hint=fix_hint,
            why_real=why_real,
            raw={},
        )
        self.ctx.findings.append(finding)
        return {"ok": True, "fingerprint": finding.fingerprint(), "total": len(self.ctx.findings)}

    def _t_mark_false_positive(self, fingerprint: str, reason: str) -> dict[str, Any]:
        before = len(self.ctx.findings)
        self.ctx.findings = [
            f for f in self.ctx.findings if f.fingerprint() != fingerprint
        ]
        removed = before - len(self.ctx.findings)
        self.ctx.suppressed.append(f"{fingerprint}: {reason}")
        return {"ok": True, "removed": removed, "total": len(self.ctx.findings)}

    def _t_task_complete(self) -> dict[str, Any]:
        self.ctx.completed = True
        self.ctx.completion_reason = "task_complete"
        return {"ok": True, "findings_total": len(self.ctx.findings)}


def _finding_summary(f: Finding) -> dict[str, Any]:
    return {
        "fingerprint": f.fingerprint(),
        "rule_id": f.rule_id,
        "severity": f.severity,
        "path": f.path,
        "line": f.line,
        "message": f.message,
        "source": f.source,
        "snippet": (f.snippet or "")[:240],
    }


def to_jsonl(records: list[ToolCallRecord]) -> str:
    import json as _json

    out = []
    for r in records:
        d = dataclasses.asdict(r)
        out.append(_json.dumps(d, default=str))
    return "\n".join(out)
