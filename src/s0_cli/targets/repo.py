"""Whole-repo target builder."""

from __future__ import annotations

from pathlib import Path

from s0_cli.targets.base import Target, TargetMode


def build_repo_target(root: Path) -> Target:
    root = root.resolve()
    if not root.exists():
        raise FileNotFoundError(f"Target path does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Repo target must be a directory: {root}")
    return Target(root=root, mode=TargetMode.REPO, label=root.name)
