# s0-cli evaluation bench

Each task is a tiny self-contained target with a `ground_truth.json` listing the expected findings.

## Splits

The bench is split into a **train** set (visible to the optimizer / proposer
agent) and a **held-out test** set (only scored at the very end of an
`s0 optimize` run, to measure generalization):

```
bench/
  tasks_train/<task_id>/
  tasks_test/<task_id>/
```

`s0 eval --split train` (the default) runs over the train set; `--split test`
runs over the held-out set. `s0 optimize` always evaluates iterations on
train, then once on test at the end.

## Per-task layout

```
bench/tasks_<split>/<task_id>/
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

## Train tasks (`bench/tasks_train/`)

| Task | What it tests |
| ---- | ------------- |
| `sql_injection_min` | classic taint: `cursor.execute` with f-string |
| `xss_template` | unescaped user input in an html template |
| `hallucinated_import` | import of a package not in lockfile and not stdlib |
| `command_injection` | `subprocess.run(..., shell=True)` and `os.system(...)` with user input |
| `weak_crypto_md5` | `hashlib.md5` for password hashing (CWE-327) |
| `yaml_unsafe_load` | `yaml.load` without `Loader=` (CWE-502) |
| `path_traversal` | `open(os.path.join("static", request.args["name"]))` (CWE-22) |

## Held-out test tasks (`bench/tasks_test/`)

These are deliberately disjoint from train and stress generalization:

| Task | What it tests |
| ---- | ------------- |
| `hardcoded_secret` | secret in source (string literal) |
| `vibe_stub_auth` | "if user == 'admin'" auth bypass — LLM-only signal |
| `pickle_deserialization` | `pickle.loads` on attacker-controlled bytes (CWE-502) |
| `jwt_no_verify` | `jwt.decode(..., options={"verify_signature": False})` (CWE-347) |

## Adding a task

1. Decide which split it belongs in (most new tasks should go in `tasks_train/`).
2. Create `bench/tasks_<split>/<id>/target/` with one or more files.
3. Write `ground_truth.json` listing the expected findings (paths relative to `target/`).
4. (Optional) `README.md` explaining the intent.
5. Run `uv run s0 eval --only <id> --split <split> --no-llm` to confirm semgrep finds (or doesn't find) what you expect.
