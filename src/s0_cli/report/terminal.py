"""Rich-based terminal renderer.

Returns a Rich ``RenderableType`` that ``console.print()`` can stream
incrementally — unlike the markdown renderer, which has to materialize a
multi-MB string and parse it through Rich's Markdown grammar (which wedges
on multi-MB inputs; see commit 7695e69 for the reproducer).

Layout — single column, NO box-drawing borders:

We tried per-severity ``Panel`` borders. They look nice when Rich's
detected terminal width matches reality — but when it doesn't (tmux,
piped output, terminal resized after launch, multiplexed CI logs) the
fixed-width ``╭───╮`` borders overflow and wrap into garbage. There's no
safe way to draw a box that survives every width-detection edge case.

Solution: use a short ``─── SEVERITY · N ──────`` chip (fixed character
budget, never overflows) plus blank lines for vertical separation.
Findings inside each section are grouped by file with a bold underlined
file path heading.

Each file path and per-finding line number is rendered as an OSC 8
hyperlink (``file:///abs/path:LINE``) — most modern terminals (iTerm2,
Cursor/VSCode integrated terminal, kitty, Alacritty, Windows Terminal,
recent Terminal.app) make those Cmd/Ctrl+clickable to jump straight to
the file in your editor. Terminals that don't support OSC 8 just print
the path text inline, so there's no downside.

Per-finding format::

    ▸ L42 · short-rule-id (source)  CWE-79
        message text wrapping naturally to the available width
        why: triage rationale from the LLM
        fix: suggested remediation
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console, Group
from rich.padding import Padding
from rich.style import Style
from rich.text import Text

from s0_cli.report._common import (
    SEV_COLOR,
    SEV_ORDER,
    group_by_file,
    short_rule_id,
)
from s0_cli.scanners.base import Finding


def _truncate(s: str | None, n: int) -> str:
    if not s:
        return ""
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _detect_width() -> int:
    """Best-effort terminal width. Falls back to 100 when not a TTY."""
    try:
        return Console().size.width
    except Exception:
        return 100


def _abs_url(path: str, workspace_root: Path | None, line: int = 0) -> str | None:
    """Build a ``file://`` URL the terminal can hyperlink to.

    Returns ``None`` if the path can't be resolved to an absolute file
    location (e.g. synthetic findings without a real path) so the caller
    falls back to plain text.

    Resolution order:
    1. If ``path`` is already absolute, use it as-is.
    2. Otherwise join with ``workspace_root`` (the scan target root).
    3. Append ``:LINE`` so editors that honour the iTerm2 / VSCode
       convention jump to the right line. Editors that don't simply
       open the file at line 1.
    """
    if not path:
        return None
    p = Path(path)
    if not p.is_absolute():
        if workspace_root is None:
            return None
        p = workspace_root / p
    try:
        # Resolve symlinks but DON'T require existence — diff mode can
        # reference paths that have since been deleted, and we still
        # want the URL to point at the right location for archaeology.
        p = p.resolve(strict=False)
    except OSError:
        return None
    url = f"file://{p}"
    if line and line > 0:
        url = f"{url}:{line}"
    return url


def _file_link(
    path: str, workspace_root: Path | None, *, base_style: str = "bold underline"
) -> Text:
    """Render a file path as a Cmd/Ctrl+clickable hyperlink (OSC 8).

    Uses ``Style(link=url)`` directly — Rich's style-string parser
    doesn't accept ``link <url>`` syntax (it expects ``link=<url>``),
    so we build the Style object explicitly to keep this simple.
    """
    url = _abs_url(path, workspace_root)
    if url is None:
        return Text(path, style=base_style)
    return Text(path, style=Style.parse(base_style) + Style(link=url))


def _finding_block(
    f: Finding, sev_color: str, workspace_root: Path | None
) -> Group:
    """Single-column block for one finding. No table, no column constraints."""
    blocks: list[Text | Padding] = []

    # Header line: ▸ L42  rule-id  (source)  CWE-XX
    head = Text()
    head.append("  ▸ ", style=sev_color)

    line_label = f"L{f.line}" if f.line else "-"
    if f.line and f.line > 0:
        url = _abs_url(f.path, workspace_root, line=f.line)
        if url is not None:
            head.append(line_label, style=Style(dim=True, link=url))
        else:
            head.append(line_label, style="dim")
    else:
        head.append(line_label, style="dim")

    head.append("  ")
    head.append(short_rule_id(f.rule_id), style="bold cyan")
    head.append(f"  ({f.source})", style="dim")
    if f.cwe:
        head.append(f"  {', '.join(f.cwe)}", style="yellow")
    blocks.append(head)

    if f.message:
        blocks.append(Padding(Text(_truncate(f.message, 600)), (0, 0, 0, 6)))
    if f.why_real:
        blocks.append(
            Padding(
                Text.from_markup(f"[dim]why:[/dim] {_truncate(f.why_real, 600)}"),
                (0, 0, 0, 6),
            )
        )
    if f.fix_hint:
        blocks.append(
            Padding(
                Text.from_markup(f"[green]fix:[/green] {_truncate(f.fix_hint, 600)}"),
                (0, 0, 0, 6),
            )
        )
    return Group(*blocks)


def _severity_section(
    sev: str,
    sev_findings: list[Finding],
    workspace_root: Path | None,
) -> Group:
    """Render one severity's findings as a borderless block.

    Header line uses a fixed-budget chip (``─── CRITICAL · 3 ───``)
    that's always ~24 chars regardless of terminal width — no overflow
    risk. Findings are grouped by file, with one block per finding.
    """
    per_file = group_by_file(sev_findings)
    sev_color = SEV_COLOR.get(sev, "")

    chip = Text()
    chip.append("─── ", style=sev_color)
    chip.append(f"{sev.upper()} · {len(sev_findings)}", style=f"bold {sev_color}")
    chip.append(" ───", style=sev_color)

    body: list = [chip, Text("")]
    for path, items in per_file.items():
        body.append(_file_link(path, workspace_root))
        for f in items:
            body.append(_finding_block(f, sev_color, workspace_root))
        body.append(Text(""))

    return Group(*body)


def to_terminal(
    findings: list[Finding],
    target_label: str = "(target)",
    *,
    width: int | None = None,
    workspace_root: Path | None = None,
) -> Group:
    """Build a Rich renderable. Caller does ``console.print(renderable)``.

    Parameters:
      width: overrides terminal-width detection (used by tests). When
        omitted, falls back to ``Console().size.width``.
      workspace_root: absolute path used to resolve relative finding
        paths into ``file://`` URLs for clickable hyperlinks. When
        omitted, hyperlinks are emitted only for findings that already
        carry an absolute path.
    """
    if not findings:
        return Group(
            Text(f"s0-cli scan: {target_label}", style="bold"),
            Text("No findings.", style="green"),
        )

    # Width is no longer needed for layout decisions (no panels), but we
    # keep the parameter for API compatibility and for the no-overflow
    # tests to pin the rendering width.
    if width is None:
        width = _detect_width()
    _ = width  # consumed by Console at print time, not by us directly

    counts: dict[str, int] = dict.fromkeys(SEV_ORDER, 0)
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    header = Text()
    header.append("s0-cli scan: ", style="bold")
    header.append(f"{target_label}\n", style="bold cyan")
    header.append(f"{len(findings)} finding(s)  ", style="bold")
    chips = [
        f"[{SEV_COLOR[sev]}]{sev}={counts[sev]}[/{SEV_COLOR[sev]}]"
        for sev in SEV_ORDER
        if counts.get(sev)
    ]
    if chips:
        header.append(Text.from_markup("  ".join(chips)))

    blocks: list = [header, Text("")]

    for sev in SEV_ORDER:
        sev_findings = [f for f in findings if f.severity == sev]
        if not sev_findings:
            continue
        blocks.append(_severity_section(sev, sev_findings, workspace_root))

    # Footer hint about clickable links — only when we actually emitted
    # any (i.e. we knew the workspace root). Cmd-click is the macOS
    # convention; on Linux/Windows it's typically Ctrl-click. Print both.
    if workspace_root is not None:
        blocks.append(Text(""))
        blocks.append(
            Text(
                "tip: Cmd/Ctrl-click any file path or line number to open in your editor",
                style="dim italic",
            )
        )

    return Group(*blocks)
