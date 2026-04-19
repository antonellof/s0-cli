# path_traversal

A `/file?name=...` endpoint that joins the user-controlled `name` directly
into a path under `static/` and `open()`s it. CWE-22 (Path Traversal) —
`?name=../../../etc/passwd` reads anything the process has access to.

semgrep should catch the pattern. Tests whether the harness reports the
fix as `os.path.realpath(...)` containment-check rather than a naive
`".." not in name` allowlist.
