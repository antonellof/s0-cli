"""Target builders: turn a CLI invocation into a normalized `Target`.

Three modes:
- repo:  the whole working tree
- diff:  files touched by `git diff <ref>`
- file:  a single file (or a small explicit list)
"""

from __future__ import annotations

from s0_cli.targets.base import Target, TargetMode
from s0_cli.targets.diff import build_diff_target
from s0_cli.targets.file import build_file_target
from s0_cli.targets.repo import build_repo_target

__all__ = [
    "Target",
    "TargetMode",
    "build_repo_target",
    "build_diff_target",
    "build_file_target",
]
