# Use s0-cli from your AI assistant

`s0-cli` ships with a built-in **MCP (Model Context Protocol) server** so any MCP-compatible client — Claude Desktop, Claude Code, Cursor, Continue, Zed, Windsurf, Cline, etc. — can use it as a tool. No copy-pasting CLI output into chat.

This guide covers:

- [What you get](#what-you-get)
- [One-time install](#one-time-install)
- [Claude Desktop](#claude-desktop)
- [Claude Code](#claude-code)
- [Cursor](#cursor)
- [Continue / Zed / Cline](#continue--zed--cline)
- [Verify the connection](#verify-the-connection)
- [Troubleshooting](#troubleshooting)

---

## What you get

Four MCP tools your agent can call:

| Tool | What it does |
|---|---|
| `scan_path(path, no_llm, scanners, exclude_scanners, harness)` | Run the hybrid SAST + LLM pipeline on a directory or file. |
| `scan_diff(repo_path, base, head, no_llm)` | Scan only the lines changed between two git refs (great for PR review). |
| `list_scanners()` | Discover available scanners. |
| `list_harnesses()` | Discover bundled harnesses. |

All tools return structured JSON. `no_llm=True` is the default — your assistant doesn't have to pay for a second LLM unless it explicitly opts in.

Plus, depending on your client:

- A **Claude Code skill** (`.claude/skills/s0-cli/SKILL.md`) that teaches the assistant *when* to call these tools.
- A **Cursor rule** (`.cursor/rules/s0-cli.mdc`) that does the same for Cursor's agent.

---

## One-time install

Pick **one** of the install methods. The MCP server lives in the `s0-cli` package itself, so installing s0-cli is enough.

### A. `uv tool install` (recommended — isolated, on $PATH)

```bash
uv tool install 's0-cli[mcp] @ git+https://github.com/antonellof/s0-cli'
```

This puts both `s0` and `s0-mcp` on your `$PATH` in an isolated venv.

### B. `pipx`

```bash
pipx install 's0-cli[mcp] @ git+https://github.com/antonellof/s0-cli'
```

### C. From a clone (developer mode)

```bash
git clone https://github.com/antonellof/s0-cli && cd s0-cli
uv sync --extra mcp
# Then use `uv run s0-mcp` instead of bare `s0-mcp` in the configs below.
```

Verify:

```bash
which s0-mcp        # should print a path
s0-mcp --help 2>/dev/null || echo "(stdio server — no --help; that's normal)"
```

### Optional: install the SAST scanners s0-cli orchestrates

For maximum coverage you'll also want the underlying tools on `$PATH`:

```bash
brew install semgrep gitleaks trivy
uv tool install bandit
uv tool install ruff
```

Without them, `s0-cli` falls back to the LLM detectors only. The MCP server still works.

### Optional: provider key for LLM triage

Only needed if your assistant calls `scan_path(no_llm=False, ...)`. Add to `~/.s0-cli.env` or pass via your MCP client's `env`:

```bash
OPENAI_API_KEY=sk-...        # or ANTHROPIC_API_KEY, OPENROUTER_API_KEY, OLLAMA_API_BASE, etc.
S0_MODEL=gpt-4o-mini          # or any litellm-supported model
```

---

## Claude Desktop

Edit (or create) the config file:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

Add an `s0-cli` server under `mcpServers`:

```json
{
  "mcpServers": {
    "s0-cli": {
      "command": "s0-mcp",
      "args": [],
      "env": {
        "OPENAI_API_KEY": "sk-..."
      }
    }
  }
}
```

If you used the developer-mode install, point `command` at the venv binary:

```json
{
  "mcpServers": {
    "s0-cli": {
      "command": "/absolute/path/to/s0-cli/.venv/bin/s0-mcp"
    }
  }
}
```

Quit and re-open Claude Desktop. Look for the 🔌 icon next to the chat input — `s0-cli` should be listed with 4 tools.

---

## Claude Code

Claude Code reads MCP servers from `~/.claude.json` (global) or `.claude.json` in the project root (per-project). Either edit it manually or use the CLI:

```bash
# Global install
claude mcp add s0-cli s0-mcp

# Or per-project
cd my-repo
claude mcp add --scope project s0-cli s0-mcp
```

Resulting `~/.claude.json` snippet:

```json
{
  "mcpServers": {
    "s0-cli": {
      "type": "stdio",
      "command": "s0-mcp",
      "args": []
    }
  }
}
```

### Bonus: install the skill

Claude Code's [skills](https://docs.claude.com/en/docs/claude-code/skills) are markdown files that teach the agent *when* to invoke a tool. This repo ships one in `.claude/skills/s0-cli/SKILL.md`. To use it globally:

```bash
mkdir -p ~/.claude/skills/s0-cli
cp .claude/skills/s0-cli/SKILL.md ~/.claude/skills/s0-cli/SKILL.md
```

Or keep it project-local — Claude Code auto-discovers `.claude/skills/*/SKILL.md` from the repo you're working in.

Restart Claude Code and ask `claude` anything like:

> Audit ./src for security issues.

It will pick up the skill, call `scan_path`, and present grouped findings.

---

## Cursor

Cursor reads `~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (per-project). Add:

```json
{
  "mcpServers": {
    "s0-cli": {
      "command": "s0-mcp",
      "args": [],
      "env": {
        "OPENAI_API_KEY": "sk-..."
      }
    }
  }
}
```

Then **Cmd-Shift-P → "Cursor: Reload MCP Servers"** (or restart Cursor). Open the **Cursor → Settings → MCP** panel — you should see `s0-cli` with a green dot and 4 tools.

### Bonus: install the rule

Cursor rules in `.cursor/rules/*.mdc` prime the agent. This repo ships one — drop it into any project where you want s0-cli to be the default security tool:

```bash
mkdir -p .cursor/rules
cp /path/to/s0-cli/.cursor/rules/s0-cli.mdc .cursor/rules/
```

Or globally via Cursor's user-level rules.

Now ask Cursor's agent:

> Run a security scan on the touched files in this branch.

It will call `scan_diff(repo_path=".", base="main", head="HEAD")` and surface findings grouped by file, with ⌘-clickable line numbers.

---

## Continue / Zed / Cline

Anything that speaks the standard MCP stdio transport works the same way. Drop the snippet into the relevant config:

- **Continue** (`~/.continue/config.json`):
  ```json
  {
    "experimental": {
      "modelContextProtocolServers": [
        { "transport": { "type": "stdio", "command": "s0-mcp" } }
      ]
    }
  }
  ```
- **Zed** (`~/.config/zed/settings.json` → `context_servers`):
  ```json
  {
    "context_servers": {
      "s0-cli": { "command": { "path": "s0-mcp", "args": [], "env": {} } }
    }
  }
  ```
- **Cline** (VS Code MCP settings panel) — paste the same `command: "s0-mcp"` into the GUI.

---

## Verify the connection

A 5-second handshake test from any shell:

```bash
( printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoketest","version":"0"}}}'
  printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
  sleep 0.3
) | s0-mcp 2>/dev/null | python3 -c 'import json,sys; [print(t["name"]) for t in json.loads(sys.stdin.read().splitlines()[-1])["result"]["tools"]]'
```

Expected output:

```
scan_path
scan_diff
list_scanners
list_harnesses
```

---

## Troubleshooting

**`command not found: s0-mcp`**
The console-script wasn't installed. Re-run with the `[mcp]` extra:
`uv tool install 's0-cli[mcp]'` or `uv sync --extra mcp` if developer-mode.

**Server connects but tools fail with "s0 not found"**
The MCP server uses subprocess to call `s0`. Make sure `s0` is on the same `$PATH` your MCP client launches the server with. On macOS, GUI apps don't always inherit your shell `$PATH` — point `command` at the absolute path: `/Users/<you>/.local/bin/s0-mcp` (or wherever `which s0-mcp` reports).

**Scans hang or time out**
Each scan has a 10-minute hard cap. Big repos with `trivy` enabled can be slow; pass `exclude_scanners: ["trivy"]` from the assistant or use `--scanner` to whitelist faster ones.

**LLM triage isn't running even with `no_llm=False`**
The MCP server inherits its environment from the client process. Check that the provider key is set in the `env` block of the MCP config, not just your shell.

**Want to see what the assistant is calling?**
Watch the MCP server's stderr. In Claude Desktop: `~/Library/Logs/Claude/mcp*.log`. In Cursor: `View → Output → MCP`.
