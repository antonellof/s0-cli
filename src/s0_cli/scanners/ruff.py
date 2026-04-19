"""ruff (security rules) scanner stub. Wired in Phase 2."""

from __future__ import annotations

import shutil

from s0_cli.scanners.base import Finding
from s0_cli.targets.base import Target


class RuffScanner:
    name = "ruff"

    def is_available(self) -> bool:
        return shutil.which("ruff") is not None

    def run(self, target: Target) -> list[Finding]:  # noqa: ARG002 - Phase 2
        return []
