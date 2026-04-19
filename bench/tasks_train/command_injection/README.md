# command_injection

A web endpoint that passes a query-string parameter directly to a shell via
`subprocess.run(..., shell=True)`. Classic CWE-78 (OS Command Injection).

Both bandit (B602) and semgrep should catch this. The harness's job is to
keep severity at **critical** and emit a clear fix hint (use the list form
of `subprocess.run` with `shell=False`).

A second endpoint uses `os.system(...)` with concatenated input — same
class of bug, different sink, exercises dedup across two scanners.
