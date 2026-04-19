"""LLM-driven 'vibe code' detector.

Catches the squishy patterns classic SAST tools miss because they're
about *intent*, not syntax:

  - Hardcoded admin/admin backdoors hidden in `if username == "admin"`
  - Stub auth like `def is_authorized(user): return user == "admin"`
  - "TODO: replace with real crypto" with weak placeholder in the meantime
  - Eval-on-untrusted-input dressed up as "config loader"
  - Dummy crypto (xor, base64-as-encryption, predictable IV)
  - Missing input validation on obviously dangerous endpoints

Implementation: walk source files, send each one (capped) to the LLM with
a strict JSON-output schema, parse responses into Findings. Synchronous
(uses litellm.completion under the hood) so it slots into the same
`Scanner` protocol as the binary scanners.

Respects `--no-llm` mode — returns [] when the underlying LLM is in stub
mode, so the bench eval can run hermetically.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from s0_cli.config import get_settings
from s0_cli.scanners.base import Finding, ScannerError, Severity, read_snippet
from s0_cli.targets.base import Target, TargetMode

_SUPPORTED_EXTS = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".java", ".php"}
_MAX_FILES = 30
_MAX_FILE_BYTES = 8_000


_VIBE_SYSTEM_PROMPT = """\
You are a senior security reviewer looking for "vibe code" — code that LOOKS
secure but isn't. Classic SAST tools miss these because they're about intent,
not syntax. Examples of what to flag:

- Hardcoded admin backdoors (`if username == "admin" and password == "admin123"`)
- Stub auth that "works" but is trivially bypassed
  (e.g. `is_authorized(user) -> user == "admin"`)
- TODO/FIXME comments admitting a security hole exists
  (e.g. `# TODO: replace with bcrypt`)
- Dummy crypto (XOR, base64 used as encryption, predictable IV/nonce)
- `eval()`/`exec()` on anything that could be user-influenced
- Missing input validation on a clearly dangerous sink
- Auth checks that ALWAYS return true / false / a constant

Do NOT flag:
- Style issues, dead code, or generic best practices
- Things any linter would catch (use of assert, missing type hints, etc.)
- Test fixtures with obvious test credentials in test files
- Secrets in environment variables (those are the *fix*, not the bug)

Output STRICT JSON. No prose, no markdown fences, just the JSON object:

{
  "findings": [
    {
      "rule_id": "vibe-<short-kebab-name>",
      "severity": "low" | "medium" | "high" | "critical",
      "line": <1-indexed int>,
      "end_line": <1-indexed int, optional>,
      "message": "<one-sentence description>",
      "cwe": ["CWE-XXX", ...],
      "confidence": <float in [0,1]>
    },
    ...
  ]
}

If nothing found: {"findings": []}.
"""


class VibeLLMScanner:
    name = "vibe_llm"

    def __init__(self) -> None:
        self._settings = get_settings()

    def is_available(self) -> bool:
        # Available iff a provider key is set. Doctor uses the same heuristic.
        return any(
            os.environ.get(k)
            for k in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GROQ_API_KEY")
        )

    def run(self, target: Target) -> list[Finding]:
        if not self.is_available():
            return []
        files = list(_pick_source_files(target))
        if not files:
            return []

        try:
            import litellm
        except ImportError as e:
            raise ScannerError("litellm not installed; vibe scanner needs it") from e

        findings: list[Finding] = []
        for path in files:
            findings.extend(self._scan_one(litellm, target.root, path))
        return findings

    def _scan_one(self, litellm: Any, root: Path | None, path: Path) -> list[Finding]:
        try:
            src = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        if not src.strip():
            return []

        truncated = src
        if len(src.encode("utf-8")) > _MAX_FILE_BYTES:
            truncated = src.encode("utf-8")[:_MAX_FILE_BYTES].decode("utf-8", errors="replace")
            truncated += "\n# ... (truncated)\n"

        rel = str(path.relative_to(root)) if root and root in path.parents else path.name
        user_msg = (
            f"File: {rel}\n"
            f"Line-numbered source (1-indexed):\n```\n"
            + _number_lines(truncated)
            + "\n```\n"
        )

        try:
            resp = litellm.completion(
                model=self._settings.model,
                messages=[
                    {"role": "system", "content": _VIBE_SYSTEM_PROMPT},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0.0,
                response_format={"type": "json_object"},
                timeout=self._settings.request_timeout_sec,
            )
        except Exception as e:  # noqa: BLE001 — provider errors should not abort the whole scan
            return [
                Finding(
                    rule_id="vibe-llm-error",
                    severity="info",
                    path=rel,
                    line=0,
                    message=f"vibe scanner LLM call failed: {type(e).__name__}: {e}",
                    source="vibe_llm",
                    confidence=0.0,
                    raw={"error": str(e)},
                )
            ]

        content = ""
        try:
            content = resp.choices[0].message.content or ""
        except (AttributeError, IndexError):
            content = ""

        return _parse_vibe_response(content, rel, root)


def _number_lines(src: str) -> str:
    return "\n".join(f"{i+1:4d}|{line}" for i, line in enumerate(src.splitlines()))


def _pick_source_files(target: Target) -> list[Path]:
    """Pick at most `_MAX_FILES` source files to keep token cost bounded."""
    if target.mode == TargetMode.FILE and target.files:
        return [Path(f) for f in target.files if Path(f).suffix in _SUPPORTED_EXTS][:_MAX_FILES]
    if not target.root or not target.root.is_dir():
        return []
    skip_dirs = {".venv", "venv", "node_modules", "__pycache__", ".git", "build", "dist"}
    out: list[Path] = []
    for ext in _SUPPORTED_EXTS:
        for p in target.root.rglob(f"*{ext}"):
            if any(part in skip_dirs for part in p.parts):
                continue
            out.append(p)
    out.sort()
    return out[:_MAX_FILES]


def _parse_vibe_response(content: str, rel_path: str, root: Path | None) -> list[Finding]:
    """Strict-ish parser: handles bare JSON, fenced JSON, and noisy preludes."""
    if not content:
        return []
    txt = content.strip()
    if txt.startswith("```"):
        # strip ```json ... ``` fences if the model ignored response_format
        first_nl = txt.find("\n")
        if first_nl >= 0:
            txt = txt[first_nl + 1 :]
        if txt.endswith("```"):
            txt = txt[:-3]
    txt = txt.strip()
    if not txt:
        return []
    try:
        data = json.loads(txt)
    except json.JSONDecodeError:
        # Try to recover the first {...} object.
        start = txt.find("{")
        end = txt.rfind("}")
        if start < 0 or end <= start:
            return []
        try:
            data = json.loads(txt[start : end + 1])
        except json.JSONDecodeError:
            return []

    items = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return []

    out: list[Finding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        line = int(item.get("line") or 0)
        end_line = int(item.get("end_line") or line)
        sev_raw = str(item.get("severity") or "medium").lower()
        if sev_raw not in {"info", "low", "medium", "high", "critical"}:
            sev_raw = "medium"
        severity: Severity = sev_raw  # type: ignore[assignment]

        cwe_field = item.get("cwe") or []
        if isinstance(cwe_field, str):
            cwe_field = [cwe_field]
        cwe = tuple(c for c in cwe_field if c)

        confidence = item.get("confidence")
        try:
            confidence_f = float(confidence) if confidence is not None else 0.7
        except (TypeError, ValueError):
            confidence_f = 0.7
        confidence_f = max(0.0, min(1.0, confidence_f))

        rule_id = str(item.get("rule_id") or "vibe-unknown")
        if not rule_id.startswith("vibe-"):
            rule_id = "vibe-" + rule_id

        message = str(item.get("message") or rule_id).strip()
        snippet = read_snippet(root, rel_path, line, end_line) if line > 0 else None

        out.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                path=rel_path,
                line=line,
                end_line=end_line,
                message=message,
                source="vibe_llm",
                cwe=cwe,
                snippet=snippet,
                confidence=confidence_f,
                raw=item,
            )
        )
    return out
