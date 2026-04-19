# s0-cli evaluation bench

Each task is a tiny self-contained target with a `ground_truth.json` listing the expected findings.

## Schema

```
bench/tasks/<task_id>/
  target/                  the code to scan (a "repo")
  ground_truth.json        list[Finding]: the labeled real findings
  README.md                what this task is testing (optional)
```

`ground_truth.json` is a JSON array; each entry has the same fields the scorer matches on:

```json
[
  {
    "rule_id": "any-string",          // not matched against; informational
    "severity": "critical|high|medium|low|info",
    "path": "target/relative/path.py",
    "line": 42,
    "cwe": ["CWE-89"],                // optional
    "note": "what's wrong here"      // optional
  }
]
```

The scorer matches a predicted finding to a label by `path` and `|line - gt.line| <= 5` (see [src/s0_cli/eval/scorer.py](../src/s0_cli/eval/scorer.py)). Severity is **scored separately**, not used for matching.

## Phase 0 tasks

| Task | What it tests |
| ---- | ------------- |
| `sql_injection_min` | classic taint: cursor.execute with f-string |
| `hardcoded_secret` | secret in source (string literal) |
| `vibe_stub_auth` | "if user == 'admin'" auth bypass — LLM-only signal |
| `hallucinated_import` | import of a package not in lockfile and not stdlib |
| `xss_template` | unescaped user input in an html template |

## Adding a task

1. Create `bench/tasks/<id>/target/` with one or more files.
2. Write `ground_truth.json` listing the expected findings (paths relative to `target/`).
3. (Optional) `README.md` explaining the intent.
4. Run `uv run s0 eval --only <id> --no-llm` to confirm semgrep finds (or doesn't find) what you expect.
