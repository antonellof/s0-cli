# sql_injection_min

Tests basic SQL injection detection. semgrep's `auto` ruleset flags this directly; the task exercises the harness's ability to keep the finding at `critical` and not false-positive on `/healthz`.
