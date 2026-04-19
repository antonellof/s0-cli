"""Scanner protocol and the normalized `Finding` shape.

`Finding` is the universal currency of the system: every scanner emits them,
every reporter consumes them, the agent triages them, the evaluator scores
them against ground truth, and the run-store archives them.

Stable across phases. Add fields with defaults; do not rename or remove.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable

if TYPE_CHECKING:
    from s0_cli.targets.base import Target

Severity = Literal["info", "low", "medium", "high", "critical"]


@dataclass(frozen=True)
class Finding:
    """One security finding, normalized across scanners.

    Fields:
        rule_id:    scanner-native rule identifier (e.g. "B602", "python.lang.security.audit.eval-detected").
        cwe:        CWE identifier(s) when known. Empty if scanner did not provide.
        severity:   one of info|low|medium|high|critical (mapped from scanner-native scale).
        path:       absolute or workspace-relative file path.
        line:       1-indexed line number of the primary location. 0 if not line-bound.
        end_line:   inclusive end of range; equals `line` for single-line findings.
        message:    short human-readable description.
        snippet:    a few lines of source around the finding (None if not extracted).
        source:     scanner name (e.g. "semgrep", "bandit", "llm:vibe-stub-auth").
        confidence: 0.0-1.0; scanners default to 1.0, the LLM triager may lower it.
        fix_hint:   optional suggested fix (LLM triager fills this in).
        why_real:   optional one-line justification (LLM triager fills this in).
        false_positive: True if the LLM triager (or a downstream harness) marked it.
        raw:        scanner's original emission, for debugging.
    """

    rule_id: str
    severity: Severity
    path: str
    line: int
    message: str
    source: str
    cwe: tuple[str, ...] = ()
    end_line: int | None = None
    snippet: str | None = None
    confidence: float = 1.0
    fix_hint: str | None = None
    why_real: str | None = None
    false_positive: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        """Stable hash for dedup across scanners and across runs.

        When a snippet is available, fingerprint = (path, line, normalized snippet) —
        this collapses the same code location flagged by different scanners to a
        single identity (e.g. semgrep + bandit both flagging an `execute(f"...")`).

        When no snippet is available, fall back to (path, line, rule family),
        which uses a coarse keyword extraction so semgrep's verbose IDs and
        bandit's terse IDs land in the same bucket for known categories.
        """
        norm_path = _normalize_path(self.path)
        if self.snippet:
            key = f"{norm_path}|{self.line}|{_normalize_snippet(self.snippet)}".encode()
        else:
            key = f"{norm_path}|{self.line}|{_rule_family(self.rule_id)}".encode()
        return hashlib.sha256(key).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint()
        d["cwe"] = list(self.cwe)
        return d


def _normalize_path(p: str) -> str:
    return str(Path(p)).replace("\\", "/")


_SNIPPET_WS_RE = re.compile(r"\s+")


def _normalize_snippet(s: str) -> str:
    return _SNIPPET_WS_RE.sub(" ", s.strip()).lower()


_RULE_FAMILY_RE = re.compile(r"[^a-zA-Z0-9]+")


def _rule_family(rule_id: str) -> str:
    """Map scanner-specific rule IDs to a coarse family for dedup.

    e.g. "python.lang.security.audit.dangerous-eval" and "B307" both contain
    "eval"; we extract the dominant token. This is a heuristic; the LLM triager
    can override dedup decisions.
    """
    parts = [p for p in _RULE_FAMILY_RE.split(rule_id.lower()) if p]
    sec_keywords = {
        "eval", "exec", "sql", "xss", "csrf", "ssrf", "rce", "lfi", "rfi",
        "deserialization", "pickle", "yaml", "shell", "subprocess", "secret",
        "credential", "password", "jwt", "auth", "crypto", "md5", "sha1",
        "random", "ssl", "tls", "redirect", "open", "path", "traversal",
        "injection", "cmd", "command", "ldap", "xpath", "xxe",
    }
    for p in parts:
        if p in sec_keywords:
            return p
    return parts[-1] if parts else rule_id.lower()


@runtime_checkable
class Scanner(Protocol):
    """Implement this to add a new detector.

    Scanners are stateless; a fresh instance is constructed per scan.
    """

    name: str

    def is_available(self) -> bool:
        """Quick check (e.g. shutil.which or `--version`) used by `s0 doctor`."""
        ...

    def run(self, target: Target) -> list[Finding]:
        """Run the scanner synchronously and return normalized findings.

        Must not raise on a clean target; return [] instead. Errors that
        prevent execution should raise `ScannerError`.
        """
        ...


class ScannerError(RuntimeError):
    """Raised when a scanner cannot run (binary missing, target invalid, etc.)."""


def normalize_to_root(path: str, root: Path | None) -> str:
    """Rewrite absolute paths to be relative to `root` when possible.

    Most scanners print absolute paths when invoked with an absolute target.
    The scorer matches on relative paths, and the LLM should see relative
    paths so it can `read_file("foo.py")` directly through the tool layer.
    """
    if not path or root is None:
        return path
    p = Path(path)
    if not p.is_absolute():
        return str(p)
    try:
        return str(p.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(p)


def read_snippet(root: Path | None, rel_path: str, line: int, end_line: int | None = None) -> str | None:
    """Read a small window of source around a finding's line range.

    Used by scanners whose JSON output omits the actual source lines
    (semgrep OSS, bandit when run without -v, etc.).
    """
    if line <= 0:
        return None
    end = end_line if end_line and end_line >= line else line
    candidates: list[Path] = []
    if root is not None:
        candidates.append((root / rel_path).resolve())
    candidates.append(Path(rel_path))
    for p in candidates:
        if not p.is_file():
            continue
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        start = max(0, line - 1)
        stop = min(len(lines), end)
        return "\n".join(lines[start:stop])
    return None
