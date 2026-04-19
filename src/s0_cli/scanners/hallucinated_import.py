"""Detect AI-hallucinated Python imports (deterministic, no LLM).

A "hallucinated import" is `import foo` where `foo` is not:
  - in the Python standard library,
  - a local module under the target tree,
  - declared in `requirements.txt` / `pyproject.toml` / `setup.py` /
    `Pipfile` / `pyproject.toml [project.dependencies]`.

These are a real-world supply-chain risk (CWE-1357: Reliance on
Insufficiently Trustworthy Component) because typosquatters scrape
LLM hallucinations and register the bogus package names on PyPI.

This scanner is intentionally mechanical — fast, deterministic, no
network. The companion `VibeLLMScanner` covers the squishier patterns
(stub auth, dummy crypto, hardcoded backdoors) that need an LLM.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

from s0_cli.scanners.base import Finding, ScannerError, read_snippet
from s0_cli.targets.base import Target, TargetMode

# Packages that are extremely common but use a different import name than
# their PyPI distribution name. Avoids false positives when requirements.txt
# lists e.g. "PyYAML" but code does `import yaml`.
_PYPI_TO_IMPORT: dict[str, set[str]] = {
    "pyyaml": {"yaml"},
    "pillow": {"pil"},
    "beautifulsoup4": {"bs4"},
    "scikit-learn": {"sklearn"},
    "python-dateutil": {"dateutil"},
    "msgpack-python": {"msgpack"},
    "opencv-python": {"cv2"},
    "protobuf": {"google.protobuf"},
    "google-cloud-storage": {"google.cloud.storage"},
    "python-jose": {"jose"},
    "pycryptodome": {"crypto"},
    "pyjwt": {"jwt"},
}


class HallucinatedImportScanner:
    name = "hallucinated_import"

    def is_available(self) -> bool:
        return True  # pure-Python; always usable

    def run(self, target: Target) -> list[Finding]:
        files = list(_pick_python_files(target))
        if not files:
            return []
        try:
            allowed = _allowed_modules(target.root, files)
        except OSError as e:
            raise ScannerError(f"could not read project metadata: {e}") from e

        findings: list[Finding] = []
        for path in files:
            findings.extend(_scan_file(target.root, path, allowed))
        return findings


def _pick_python_files(target: Target) -> list[Path]:
    if target.mode == TargetMode.FILE and target.files:
        return [Path(f) for f in target.files if str(f).endswith(".py")]
    if not target.root or not target.root.is_dir():
        return []
    skip_dirs = {".venv", "venv", "node_modules", "__pycache__", ".git", "build", "dist"}
    out: list[Path] = []
    for p in target.root.rglob("*.py"):
        if any(part in skip_dirs for part in p.parts):
            continue
        out.append(p)
    return sorted(out)


def _allowed_modules(root: Path, files: list[Path]) -> set[str]:
    """Set of top-level module names that are not hallucinations.

    Includes: stdlib + builtin module names, declared dependencies (with
    PyPI-name -> import-name aliasing), and local modules (any .py file
    or directory-with-__init__.py under target.root).
    """
    allowed: set[str] = set()
    allowed.update(sys.stdlib_module_names)
    allowed.update(sys.builtin_module_names)
    allowed.update(_local_modules(root, files))
    allowed.update(_declared_dependencies(root))
    # Always-acceptable common runtime names.
    allowed.update({"__future__", "typing_extensions"})
    return {a.lower() for a in allowed}


def _local_modules(root: Path, files: list[Path]) -> set[str]:
    out: set[str] = set()
    for f in files:
        try:
            rel = f.relative_to(root)
        except ValueError:
            rel = Path(f.name)
        parts = rel.with_suffix("").parts
        if not parts:
            continue
        out.add(parts[0])
        if len(parts) > 1:
            out.add(rel.parts[0])  # top-level package dir
    # also: any subdir with an __init__.py becomes a top-level package
    if root.is_dir():
        for p in root.iterdir():
            if p.is_dir() and (p / "__init__.py").is_file():
                out.add(p.name)
    return out


_REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)")


def _declared_dependencies(root: Path) -> set[str]:
    out: set[str] = set()

    req = root / "requirements.txt"
    if req.is_file():
        for raw in req.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = _REQ_LINE_RE.match(line)
            if m:
                out.add(m.group(1).lower())

    pp = root / "pyproject.toml"
    if pp.is_file():
        try:
            text = pp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        # Cheap regex extraction; avoids requiring tomllib for older targets.
        for m in re.finditer(r'"([A-Za-z0-9_.\-]+)\s*[<>=!~]?', text):
            out.add(m.group(1).lower())

    pipfile = root / "Pipfile"
    if pipfile.is_file():
        for m in re.finditer(
            r'^([A-Za-z0-9_.\-]+)\s*=', pipfile.read_text(encoding="utf-8", errors="replace"), re.M,
        ):
            out.add(m.group(1).lower())

    expanded = set(out)
    for pypi_name in out:
        for import_name in _PYPI_TO_IMPORT.get(pypi_name, set()):
            expanded.add(import_name.lower())
    return expanded


def _scan_file(root: Path | None, path: Path, allowed: set[str]) -> list[Finding]:
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError:
        return []

    findings: list[Finding] = []
    rel = str(path.relative_to(root)) if root and root in path.parents else path.name

    for node in ast.walk(tree):
        names: list[tuple[str, int]] = []
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.append((alias.name.split(".")[0], node.lineno))
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                continue  # relative import; always local-by-construction
            mod = (node.module or "").split(".")[0]
            if mod:
                names.append((mod, node.lineno))

        for top, line in names:
            if top.lower() in allowed:
                continue
            findings.append(
                Finding(
                    rule_id="vibe-hallucinated-import",
                    severity="high",
                    path=rel,
                    line=line,
                    end_line=line,
                    message=(
                        f"Imports {top!r} which is not stdlib, not a local module, "
                        f"and not declared in requirements/pyproject. Likely an AI "
                        f"hallucination — typosquat risk (CWE-1357)."
                    ),
                    source="hallucinated_import",
                    cwe=("CWE-1357",),
                    snippet=read_snippet(root, rel, line),
                    confidence=0.9,
                    raw={"module": top, "file": rel},
                )
            )
    return findings
