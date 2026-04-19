"""The `Target` dataclass that every scanner and harness consumes."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class TargetMode(str, Enum):
    REPO = "repo"
    DIFF = "diff"
    FILE = "file"


@dataclass(frozen=True)
class Target:
    """A normalized scan target.

    Fields:
        root:      workspace root (absolute). Scanners chdir here when needed.
        mode:      repo | diff | file.
        files:     explicit file list when mode is diff or file. Empty for repo
                   means "whole tree" (scanners use their own discovery).
        diff_ref:  the git ref the diff was taken against (only set in diff mode).
        label:     human-readable name for logging (defaults to root basename).
    """

    root: Path
    mode: TargetMode
    files: tuple[Path, ...] = ()
    diff_ref: str | None = None
    label: str = ""
    languages: tuple[str, ...] = field(default_factory=tuple)

    def relative_files(self) -> tuple[str, ...]:
        out = []
        for f in self.files:
            try:
                out.append(str(f.relative_to(self.root)))
            except ValueError:
                out.append(str(f))
        return tuple(out)

    def display(self) -> str:
        return self.label or self.root.name or str(self.root)
