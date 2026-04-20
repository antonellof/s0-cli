"""SARIF 2.1.0 emitter.

Hand-rolled (avoids the heavy `sarif-om` dep). Conforms to the subset GitHub
Code Scanning expects: $schema, version, runs[].tool.driver, runs[].results[].

References:
- https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
- https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
"""

from __future__ import annotations

import json

from s0_cli.scanners.base import Finding

_LEVEL_MAP = {
    "info": "note",
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}


def to_sarif(findings: list[Finding], tool_name: str = "s0-cli", tool_version: str = "0.3.0") -> str:
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.rule_id},
                "fullDescription": {"text": f.message[:500]},
                "defaultConfiguration": {"level": _LEVEL_MAP.get(f.severity, "warning")},
                "properties": {
                    "tags": ["security"] + list(f.cwe),
                    "security-severity": _security_severity(f.severity),
                },
            }
        result = {
            "ruleId": f.rule_id,
            "level": _LEVEL_MAP.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.path},
                        "region": {
                            "startLine": max(1, f.line),
                            "endLine": max(1, f.end_line or f.line),
                        },
                    }
                }
            ],
            "partialFingerprints": {"primaryLocationLineHash": f.fingerprint()},
            "properties": {
                "source": f.source,
                "confidence": f.confidence,
                "severity": f.severity,
                "cwe": list(f.cwe),
            },
        }
        if f.fix_hint:
            result["fixes"] = [{"description": {"text": f.fix_hint}}]
        if f.why_real:
            result["properties"]["why_real"] = f.why_real
        if f.snippet:
            result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": f.snippet[:1000]
            }
        results.append(result)

    sarif = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/s0-cli/s0-cli",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _security_severity(sev: str) -> str:
    return {
        "info": "1.0",
        "low": "3.0",
        "medium": "5.5",
        "high": "7.5",
        "critical": "9.5",
    }.get(sev, "5.0")
