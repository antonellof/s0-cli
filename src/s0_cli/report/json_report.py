"""JSON report writer."""

from __future__ import annotations

import json

from s0_cli.scanners.base import Finding


def to_json(findings: list[Finding]) -> str:
    return json.dumps(
        {
            "version": "0.0.1",
            "count": len(findings),
            "findings": [f.to_dict() for f in findings],
        },
        indent=2,
        default=str,
    )
