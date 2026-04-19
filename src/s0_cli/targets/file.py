"""Single-file (or short list) target builder."""

from __future__ import annotations

from pathlib import Path

from s0_cli.targets.base import Target, TargetMode


def build_file_target(paths: list[Path], root: Path | None = None) -> Target:
    paths = [p.resolve() for p in paths]
    for p in paths:
        if not p.exists():
            raise FileNotFoundError(f"File does not exist: {p}")
    if root is None:
        root = paths[0].parent
    root = root.resolve()
    return Target(
        root=root,
        mode=TargetMode.FILE,
        files=tuple(paths),
        label=", ".join(p.name for p in paths[:3]) + ("..." if len(paths) > 3 else ""),
    )
