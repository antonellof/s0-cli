---
name: s0-cli
description: Use s0-cli — a local hybrid SAST + LLM security agent — to scan code for vulnerabilities and "vibe-code" problems (stub auth, hallucinated imports, dummy crypto, prompt-injection sinks). Use when the user asks to audit, review for security, find vulnerabilities, scan a directory / file / PR / diff, or check if AI-generated code is safe to ship.
---

# s0-cli

`s0-cli` is a Meta-Harness-shaped agent that runs five deterministic SAST scanners (semgrep, bandit, ruff, gitleaks, trivy) plus two LLM detectors (hallucinated-import, vibe-code), then deduplicates and triages the results.

## When to use

Trigger this skill whenever the user:

- asks to **scan / audit / review** a repo, file, or directory for security issues
- mentions **vulnerabilities**, **CVEs**, **CWE-XXX**, **OWASP**, **SAST**, **DAST**
- asks if some AI-generated code is **safe to ship** or has **vibe-code** smells
- asks for a **PR security review** or **diff scan**
- asks about **secrets**, **hardcoded credentials**, **SQL injection**, **XSS**, **SSRF**, **path traversal**, **insecure deserialization**, **command injection**, **weak crypto**

## How to invoke

There are two equivalent surfaces. Use whichever the host environment exposes.

### A. MCP tools (preferred)

If `s0-cli` is configured as an MCP server (the typical setup — see `docs/integrations/INSTALL.md`), use the registered tools:

- `scan_path(path, no_llm=true, scanners=None, exclude_scanners=None)` — scan a directory or file
- `scan_diff(repo_path, base="HEAD~1", head="HEAD", no_llm=true)` — scan only the diff between two refs
- `list_scanners()` — discover available scanner names
- `list_harnesses()` — discover bundled harnesses

**Default to `no_llm=true`.** s0-cli's LLM triage is a separate paid LLM call. Since you (the assistant) are already an LLM, the user almost never wants to be billed twice. Only set `no_llm=false` when the user explicitly asks for "deep triage", "explanations", or "with LLM".

### B. Shell command (fallback)

If MCP is not available, shell out to the `s0` binary:

```bash
# Whole repo, fast (no LLM)
s0 scan ./path --no-llm --format json --out /tmp/scan.json --quiet
# PR diff
s0 scan --diff main..HEAD --no-llm --format json --out /tmp/scan.json --quiet
# One scanner only
s0 scan ./path --scanner bandit --no-llm --format json --out /tmp/scan.json --quiet
```

Always pass `--format json --out <file> --quiet` so the JSON doesn't intermix with progress output.

## Reading the results

Each finding has the shape:

```jsonc
{
  "path": "src/api/users.py",
  "line": 42,
  "severity": "critical | high | medium | low | info",
  "rule_id": "B608",       // scanner-native ID
  "message": "Possible SQL injection via string concatenation.",
  "cwe": "CWE-89",         // optional
  "source": "bandit",      // which scanner produced it
  "why": "...",            // optional, only with LLM triage
  "fix": "..."             // optional, only with LLM triage
}
```

Group by `severity` (highest first), then by `path`. When summarizing for the user, lead with **critical** and **high** findings, mention totals per severity, and quote the offending line numbers so the user can jump to them.

## Things to avoid

- **Don't** dump 200 raw findings into chat. If the count is high, summarize per file, surface the worst N, and offer to filter by severity or scanner.
- **Don't** invoke `scan_path` on the entire user home directory or `/`. Confirm the scope first.
- **Don't** turn on `no_llm=false` silently — call out the cost first.
- **Don't** treat `s0` output as ground truth. SAST has false positives; cross-check with the surrounding code before recommending fixes.

## Worked example

User: *"Can you check ./api for SQL injection issues?"*

You should:

1. Call `scan_path(path="./api", no_llm=True, scanners=["bandit", "semgrep"])` (these two cover SQLi best).
2. Filter the returned findings to those mentioning `sql`, `B608`, `B610`, or CWE-89.
3. Present them grouped by file, with line numbers and a one-line fix suggestion.
