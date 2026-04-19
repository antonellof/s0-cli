"""Report writers: SARIF (industry standard), JSON, Markdown.

All consume `list[Finding]` and produce a string (the caller writes to file).
"""

from s0_cli.report.json_report import to_json
from s0_cli.report.markdown import to_markdown
from s0_cli.report.sarif import to_sarif

__all__ = ["to_sarif", "to_json", "to_markdown"]
