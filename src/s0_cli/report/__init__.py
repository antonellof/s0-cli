"""Report writers.

Two flavours:

- *String* writers (markdown, json, sarif, csv, gitlab, junit) — return a
  serializable string that the CLI writes to a file or stdout. Safe to
  pipe through ``grep`` / ``jq`` etc.

- *Renderable* writer (terminal) — returns a Rich ``RenderableType`` that
  the CLI prints directly via ``console.print``. Streams incrementally so
  it doesn't wedge on huge result sets the way a multi-MB Markdown string
  through Rich's Markdown grammar does.
"""

from s0_cli.report.csv_report import to_csv
from s0_cli.report.gitlab import to_gitlab_codequality
from s0_cli.report.json_report import to_json
from s0_cli.report.junit_xml import to_junit_xml
from s0_cli.report.markdown import to_markdown
from s0_cli.report.sarif import to_sarif
from s0_cli.report.terminal import to_terminal

__all__ = [
    "to_sarif",
    "to_json",
    "to_markdown",
    "to_csv",
    "to_gitlab_codequality",
    "to_junit_xml",
    "to_terminal",
]
