"""Cheap pre-flight check on a candidate harness file.

Catches obvious problems (no Harness subclass, missing `name`, forbidden
imports, syntax errors) without running the LLM. The Phase-1 proposer should
call `validate_harness()` before requesting a full eval.
"""

from __future__ import annotations

import ast
import importlib.util
from dataclasses import dataclass, field
from pathlib import Path

FORBIDDEN_IMPORTS = {
    "subprocess",
    "os.system",
    "shutil.rmtree",
    "requests",
    "urllib.request",
    "socket",
}

ALLOWED_INTERNAL = {
    "s0_cli.harness",
    "s0_cli.scanners",
    "s0_cli.targets",
    "s0_cli.config",
}


@dataclass
class ValidationReport:
    ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    harness_class: str | None = None


def validate_harness(path: Path) -> ValidationReport:
    report = ValidationReport(ok=True)

    if not path.exists():
        report.ok = False
        report.errors.append(f"File not found: {path}")
        return report

    src = path.read_text(encoding="utf-8")

    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError as e:
        report.ok = False
        report.errors.append(f"SyntaxError: {e}")
        return report

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _check_import(alias.name, report)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            _check_import(mod, report)

    harness_classes = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                base_name = _attr_name(base)
                if base_name and base_name.endswith("Harness"):
                    harness_classes.append(node.name)

    if not harness_classes:
        report.ok = False
        report.errors.append("No class subclassing Harness found.")
    elif len(harness_classes) > 1:
        report.warnings.append(
            f"Multiple Harness subclasses found: {harness_classes}. Only the first will be loaded."
        )
    if harness_classes:
        report.harness_class = harness_classes[0]

    spec = importlib.util.spec_from_file_location("_s0_validate", path)
    if spec is None or spec.loader is None:
        report.warnings.append("Could not build import spec for runtime validation.")
        return report
    try:
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as e:  # broad: candidate code may explode
        report.ok = False
        report.errors.append(f"Import failed: {type(e).__name__}: {e}")
        return report

    if report.harness_class:
        cls = getattr(module, report.harness_class, None)
        if cls is None:
            report.ok = False
            report.errors.append(f"Class {report.harness_class} not found after import.")
        else:
            name_attr = getattr(cls, "name", "")
            if not name_attr:
                report.ok = False
                report.errors.append("Harness.name is empty.")
            elif name_attr != path.stem:
                report.warnings.append(
                    f"Harness.name={name_attr!r} does not match filename {path.stem!r}."
                )

    return report


def _check_import(mod: str, report: ValidationReport) -> None:
    if not mod:
        return
    if mod in FORBIDDEN_IMPORTS or any(mod.startswith(f + ".") for f in FORBIDDEN_IMPORTS):
        report.warnings.append(
            f"Import of {mod!r} is discouraged; the harness should use the tools layer."
        )
    if mod.startswith("s0_cli.eval") or mod.startswith("s0_cli.runs"):
        report.ok = False
        report.errors.append(f"Forbidden import: {mod} (would let harness see scoring/run-store).")


def _attr_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None
