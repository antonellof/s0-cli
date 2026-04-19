"""Git diff target builder.

Uses `git diff --name-only <ref>...HEAD` to enumerate touched files; falls back
to `git diff --name-only <ref>` (two-dot) if three-dot fails.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from s0_cli.targets.base import Target, TargetMode


def build_diff_target(root: Path, ref: str) -> Target:
    root = root.resolve()
    if not (root / ".git").exists():
        raise RuntimeError(f"Not a git repository: {root}")

    files = _git_diff_names(root, ref)
    abs_files = tuple((root / f).resolve() for f in files if (root / f).exists())
    return Target(
        root=root,
        mode=TargetMode.DIFF,
        files=abs_files,
        diff_ref=ref,
        label=f"{root.name}@{ref}",
    )


def _git_diff_names(root: Path, ref: str) -> list[str]:
    for spec in (f"{ref}...HEAD", ref):
        try:
            out = subprocess.run(
                ["git", "diff", "--name-only", spec],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
            )
            return [line.strip() for line in out.stdout.splitlines() if line.strip()]
        except subprocess.CalledProcessError:
            continue
    raise RuntimeError(f"git diff failed for ref {ref!r} in {root}")
