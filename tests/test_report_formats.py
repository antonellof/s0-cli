"""Tests for the report writers (CSV, GitLab, JUnit, terminal, markdown).

Focus is contract-level: each writer must be deterministic, escape user
input safely, and survive empty / minimal / fully-populated findings.
The exact whitespace of human-readable formats is intentionally not
asserted — only the presence of key fields, so we don't pin tests to
cosmetic tweaks.
"""

from __future__ import annotations

import csv as csv_module
import io
import json
import xml.etree.ElementTree as ET

import pytest
from rich.console import Console

from s0_cli.report import (
    to_csv,
    to_gitlab_codequality,
    to_junit_xml,
    to_markdown,
    to_terminal,
)
from s0_cli.report._common import group_by_file, short_rule_id, sort_findings
from s0_cli.scanners.base import Finding


def mk(
    *,
    rule_id: str = "rule",
    severity: str = "medium",
    path: str = "src/app.py",
    line: int = 10,
    message: str = "msg",
    source: str = "semgrep",
    cwe: tuple[str, ...] = (),
    snippet: str | None = None,
    why_real: str | None = None,
    fix_hint: str | None = None,
    confidence: float = 0.9,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        path=path,
        line=line,
        message=message,
        source=source,
        cwe=cwe,
        snippet=snippet,
        why_real=why_real,
        fix_hint=fix_hint,
        confidence=confidence,
    )


@pytest.fixture
def sample_findings() -> list[Finding]:
    return [
        mk(
            rule_id="generic.secrets.security.detected-username-and-password-in-uri.detected-username-and-password-in-uri",
            severity="critical",
            path="db/README.md",
            line=187,
            message="Hardcoded production credentials.",
            cwe=("CWE-798", "CWE-312"),
            why_real="Real RDS hostname with real password.",
            fix_hint="Rotate credentials and remove from git history.",
        ),
        mk(
            rule_id="python.lang.security.use-defused-xml.use-defused-xml",
            severity="medium",
            path="bot/news_fetcher.py",
            line=10,
            message="Native xml.etree vulnerable to XXE.",
            cwe=("CWE-611",),
        ),
        mk(
            rule_id="B105",
            severity="low",
            path="bot/news_fetcher.py",
            line=22,
            message="Possible hardcoded password.",
            source="bandit",
        ),
    ]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


class TestShortRuleId:
    def test_strips_duplicated_trailing_segment(self):
        rid = (
            "generic.secrets.security.detected-username-and-password-in-uri."
            "detected-username-and-password-in-uri"
        )
        out = short_rule_id(rid)
        assert "detected-username-and-password-in-uri" in out
        # Trailing duplicated segment must be gone.
        assert not out.endswith(".detected-username-and-password-in-uri.detected-username-and-password-in-uri")

    def test_collapses_long_to_leaf(self):
        rid = "a.b.c.d.e.f.really-long-rule-id-name-that-pushes-over-sixty-chars"
        out = short_rule_id(rid)
        assert out == "really-long-rule-id-name-that-pushes-over-sixty-chars"

    def test_keeps_short_ids(self):
        assert short_rule_id("B105") == "B105"

    def test_empty_safe(self):
        assert short_rule_id("") == "(no rule id)"


class TestGrouping:
    def test_group_by_file_sorted_by_severity(self):
        findings = [
            mk(severity="low", path="a.py", line=2),
            mk(severity="critical", path="a.py", line=10),
            mk(severity="medium", path="b.py", line=1),
        ]
        grouped = group_by_file(findings)
        # File order should follow the highest-severity finding's path order.
        assert list(grouped.keys()) == ["a.py", "b.py"]
        # Within a file: severity desc then line asc.
        assert [f.severity for f in grouped["a.py"]] == ["critical", "low"]

    def test_sort_is_deterministic(self):
        findings = [
            mk(severity="medium", path="z.py", line=1),
            mk(severity="medium", path="a.py", line=5),
            mk(severity="medium", path="a.py", line=2),
            mk(severity="critical", path="m.py", line=1),
        ]
        sorted1 = sort_findings(findings)
        sorted2 = sort_findings(list(reversed(findings)))
        assert [(f.severity, f.path, f.line) for f in sorted1] == [
            (f.severity, f.path, f.line) for f in sorted2
        ]


# ---------------------------------------------------------------------------
# csv
# ---------------------------------------------------------------------------


class TestCsv:
    def test_round_trip_columns(self, sample_findings):
        out = to_csv(sample_findings)
        rows = list(csv_module.DictReader(io.StringIO(out)))
        assert len(rows) == 3
        # Critical first.
        assert rows[0]["severity"] == "critical"
        assert rows[0]["path"] == "db/README.md"
        assert rows[0]["line"] == "187"
        # CWE list is semicolon-joined for spreadsheet friendliness.
        assert rows[0]["cwe"] == "CWE-798;CWE-312"

    def test_empty_findings(self):
        out = to_csv([])
        rows = list(csv_module.DictReader(io.StringIO(out)))
        assert rows == []
        assert "severity," in out  # header always emitted

    def test_newlines_in_message_flattened(self):
        out = to_csv([mk(message="line1\nline2\n  line3")])
        rows = list(csv_module.DictReader(io.StringIO(out)))
        assert "\n" not in rows[0]["message"]
        assert rows[0]["message"] == "line1 line2 line3"


# ---------------------------------------------------------------------------
# gitlab Code Quality
# ---------------------------------------------------------------------------


class TestGitlab:
    def test_schema_minimal(self, sample_findings):
        out = to_gitlab_codequality(sample_findings)
        data = json.loads(out)
        assert isinstance(data, list)
        assert len(data) == 3
        first = data[0]
        # Required GitLab Code Quality fields.
        for key in ("type", "check_name", "description", "severity", "fingerprint", "location"):
            assert key in first, f"missing {key}"
        assert first["type"] == "issue"
        assert first["location"]["path"] == "db/README.md"
        assert first["location"]["lines"]["begin"] == 187

    def test_severity_mapping(self):
        out = to_gitlab_codequality(
            [
                mk(severity="critical"),
                mk(severity="high"),
                mk(severity="medium"),
                mk(severity="low"),
                mk(severity="info"),
            ]
        )
        data = json.loads(out)
        sevs = sorted({d["severity"] for d in data})
        # blocker (critical), critical (high), major, minor, info
        assert "blocker" in sevs and "major" in sevs and "minor" in sevs

    def test_fingerprints_unique_and_stable(self, sample_findings):
        a = json.loads(to_gitlab_codequality(sample_findings))
        b = json.loads(to_gitlab_codequality(sample_findings))
        fps_a = [d["fingerprint"] for d in a]
        fps_b = [d["fingerprint"] for d in b]
        assert fps_a == fps_b
        assert len(set(fps_a)) == len(fps_a)

    def test_vibe_finding_categorized_as_bug_risk(self):
        f = mk(source="vibe_llm")
        data = json.loads(to_gitlab_codequality([f]))
        assert "Bug Risk" in data[0]["categories"]

    def test_empty(self):
        assert json.loads(to_gitlab_codequality([])) == []


# ---------------------------------------------------------------------------
# junit xml
# ---------------------------------------------------------------------------


class TestJunit:
    def test_parses_as_valid_xml(self, sample_findings):
        out = to_junit_xml(sample_findings)
        root = ET.fromstring(out)
        assert root.tag == "testsuites"
        assert root.attrib["tests"] == "3"
        assert root.attrib["failures"] == "3"

    def test_one_suite_per_severity(self, sample_findings):
        root = ET.fromstring(to_junit_xml(sample_findings))
        suites = root.findall("testsuite")
        names = [s.attrib["name"] for s in suites]
        assert "s0-cli/critical" in names
        assert "s0-cli/medium" in names
        assert "s0-cli/low" in names

    def test_failure_body_includes_metadata(self, sample_findings):
        root = ET.fromstring(to_junit_xml(sample_findings))
        crit = root.find("testsuite[@name='s0-cli/critical']/testcase/failure")
        assert crit is not None
        body = crit.text or ""
        assert "rule:" in body
        assert "source: semgrep" in body
        assert "CWE-798" in body
        # `why:` was supplied for the critical finding.
        assert "why:" in body

    def test_xml_escapes_special_chars(self):
        f = mk(message='bad <tag> & "quotes"', path="x<y>.py")
        root = ET.fromstring(to_junit_xml([f]))
        tc = root.find(".//testcase")
        assert tc is not None
        # Round-trip through ET means escaping was correct.
        assert tc.attrib["classname"] == "x<y>.py"

    def test_empty(self):
        out = to_junit_xml([])
        root = ET.fromstring(out)
        assert root.attrib["tests"] == "0"


# ---------------------------------------------------------------------------
# markdown
# ---------------------------------------------------------------------------


class TestMarkdown:
    def test_header_summary(self, sample_findings):
        out = to_markdown(sample_findings, target_label="myproj")
        assert "# s0-cli scan: myproj" in out
        assert "Total findings: **3**" in out

    def test_grouped_by_file(self, sample_findings):
        out = to_markdown(sample_findings)
        # Each unique file gets its own section heading.
        assert "### `db/README.md`" in out
        assert "### `bot/news_fetcher.py`" in out

    def test_short_rule_id_used(self, sample_findings):
        out = to_markdown(sample_findings)
        # Doubled `.foo.foo` suffix stripped.
        assert ".detected-username-and-password-in-uri.detected-username-and-password-in-uri" not in out

    def test_pipe_chars_escaped(self):
        f = mk(message="a | b | c")
        out = to_markdown([f])
        # No raw pipes inside the table cell — they'd break the table.
        assert "a \\| b \\| c" in out

    def test_empty(self):
        out = to_markdown([], target_label="empty")
        assert "No findings." in out


# ---------------------------------------------------------------------------
# terminal (rich renderable)
# ---------------------------------------------------------------------------


class TestTerminal:
    def _capture(self, renderable, width: int = 140, links: bool = False) -> str:
        """Render to a StringIO so we can assert exact output.

        ``links`` toggles OSC 8 hyperlink emission. Defaults to False
        (plain output) so length assertions match visible width — when
        True, escape codes appear in the buffer and len() != visible.
        """
        buf = io.StringIO()
        Console(
            file=buf,
            force_terminal=links,
            width=width,
            color_system=None if not links else "truecolor",
            legacy_windows=False,
        ).print(renderable)
        return buf.getvalue()

    def test_renders_findings(self, sample_findings):
        r = to_terminal(sample_findings, target_label="myproj", width=140)
        out = self._capture(r, width=140)
        assert "myproj" in out
        assert "CRITICAL" in out
        assert "MEDIUM" in out
        # Rule IDs short-form.
        assert "use-defused-xml" in out
        # File path shown.
        assert "db/README.md" in out

    def test_empty_renders_no_findings(self):
        out = self._capture(to_terminal([], target_label="clean"))
        assert "clean" in out
        assert "No findings" in out

    def test_severity_chips_in_header(self, sample_findings):
        r = to_terminal(sample_findings, width=140)
        out = self._capture(r, width=140)
        assert "critical=1" in out
        assert "medium=1" in out
        assert "low=1" in out

    def test_why_and_fix_inlined(self, sample_findings):
        r = to_terminal(sample_findings, width=140)
        out = self._capture(r, width=140)
        assert "why:" in out
        assert "fix:" in out

    @pytest.mark.parametrize("width", [40, 50, 60, 79, 80, 99, 100, 120, 200])
    def test_no_line_overflows_terminal_width(self, sample_findings, width):
        """Every rendered line must fit within the declared width.

        This is the regression guard for the misalignment bug: at any
        width the renderer must produce lines ≤ width.
        """
        r = to_terminal(sample_findings, width=width)
        out = self._capture(r, width=width)
        for line in out.splitlines():
            assert len(line) <= width, (
                f"line wider than terminal ({len(line)} > {width}): {line!r}"
            )

    @pytest.mark.parametrize("width", [40, 60, 80, 100, 140, 200])
    def test_no_box_drawing_borders_at_any_width(self, sample_findings, width):
        """Panel borders are forbidden — they overflow when Rich's
        detected width disagrees with the actual terminal (tmux, piped,
        resized after launch). Locked in by this regression test.
        """
        out = self._capture(to_terminal(sample_findings, width=width), width=width)
        for forbidden in ("╭", "╮", "╰", "╯", "┏", "┓", "┗", "┛", "│"):
            assert forbidden not in out, (
                f"box-drawing char {forbidden!r} leaked at width={width}; "
                "this is the bug that overflows narrow terminals"
            )
        # Severity chip ─── CRITICAL · 1 ─── must still be present so
        # sections are visually distinct.
        assert "CRITICAL" in out
        assert "───" in out

    def test_single_column_layout_no_table_grid(self, sample_findings):
        """The renderer must NOT emit Rich's table column separators.

        Locks in the design choice: single-column always (no 4-col table
        grid that broke at narrow widths). Table.grid never produces
        these characters because it uses padding only, but if anyone
        re-introduces a bordered Table this test will catch it.
        """
        r = to_terminal(sample_findings, width=140)
        out = self._capture(r, width=140)
        # Vertical bars between table columns indicate a gridded table.
        assert "│ L" not in out  # no "│ L42 │ rule │ ..." pattern
        # The ▸ marker is the per-finding header bullet — must appear.
        assert "▸" in out

    def test_preserves_all_finding_data_at_any_width(self, sample_findings):
        """Width changes affect framing only, never drop data."""
        for w in (40, 80, 200):
            out = self._capture(to_terminal(sample_findings, width=w), width=w)
            assert "db/README.md" in out
            assert "bot/news_fetcher.py" in out
            assert "why:" in out
            assert "fix:" in out

    def test_long_message_wraps_no_truncation(self):
        """Long messages must wrap, not be silently chopped per line."""
        long_msg = (
            "This is a particularly verbose security finding description that "
            "would absolutely overflow a small terminal if the renderer did "
            "not wrap properly across multiple lines preserving all the words "
            "intact for the engineer reading the report."
        )
        f = mk(message=long_msg, severity="high")
        r = to_terminal([f], width=60)
        out = self._capture(r, width=60)
        flat = " ".join(out.split())
        assert long_msg in flat


class TestTerminalHyperlinks:
    """OSC 8 file:// hyperlinks for cmd/ctrl-clickable file paths."""

    def _capture_with_links(self, renderable, width: int = 140) -> str:
        buf = io.StringIO()
        Console(
            file=buf,
            force_terminal=True,
            color_system="truecolor",
            width=width,
            legacy_windows=False,
        ).print(renderable)
        return buf.getvalue()

    def test_emits_osc8_hyperlink_for_relative_path(self, tmp_path, sample_findings):
        """Relative paths get joined with workspace_root → file:// URL.

        Rich emits OSC 8 as ``ESC ] 8 ; id=N ; URL ESC \\`` — match on
        the ``;file://`` portion which is invariant. ``tmp_path`` is
        already resolved by pytest so no symlink resolution surprises.
        """
        r = to_terminal(sample_findings, width=120, workspace_root=tmp_path)
        out = self._capture_with_links(r)
        # OSC 8 hyperlink with file:// URL — Rich adds an `id=N;` param.
        assert "\x1b]8;" in out and ";file://" in out
        # Resolved path includes the workspace root.
        assert f"file://{tmp_path}" in out
        # Specifically: db/README.md becomes <tmp>/db/README.md.
        assert "db/README.md" in out

    def test_emits_line_anchor_in_url(self, tmp_path):
        """Line numbers should be embedded as :LINE in the URL."""
        f = mk(severity="high", path="src/handler.py", line=42)
        r = to_terminal([f], width=120, workspace_root=tmp_path)
        out = self._capture_with_links(r)
        assert f"file://{tmp_path}/src/handler.py:42" in out

    def test_no_hyperlink_without_workspace_root(self, sample_findings):
        """Without a workspace root, relative paths get no link.

        ``sample_findings`` are all relative, so none of them should
        produce ``file://`` URLs in the output.
        """
        r = to_terminal(sample_findings, width=120, workspace_root=None)
        out = self._capture_with_links(r)
        # No file:// URL anywhere — relative paths can't be resolved.
        assert "file://" not in out
        # Footer hint about clickable links should also be absent.
        assert "Cmd/Ctrl-click" not in out

    def test_absolute_paths_link_without_workspace_root(self, tmp_path):
        """Findings carrying absolute paths should still link.

        Use a real absolute path (tmp_path) to avoid macOS's
        ``/etc → /private/etc`` symlink that ``Path.resolve()``
        follows — the underlying behaviour is correct, but it would
        make the assertion path-dependent.
        """
        abs_file = tmp_path / "config.py"
        abs_file.write_text("x = 1\n")
        f = mk(severity="high", path=str(abs_file), line=10)
        r = to_terminal([f], width=120, workspace_root=None)
        out = self._capture_with_links(r)
        assert f"file://{abs_file}:10" in out

    def test_footer_hint_when_workspace_root_provided(self, tmp_path, sample_findings):
        r = to_terminal(sample_findings, width=120, workspace_root=tmp_path)
        out = self._capture_with_links(r)
        assert "Cmd/Ctrl-click" in out

    def test_synthetic_finding_without_path_is_safe(self, tmp_path):
        """A finding with empty path mustn't crash — just no link."""
        f = mk(severity="info", path="", line=0)
        r = to_terminal([f], width=120, workspace_root=tmp_path)
        # Should render without raising.
        out = self._capture_with_links(r)
        assert "info" in out.lower() or "INFO" in out
