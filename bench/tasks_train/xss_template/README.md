# xss_template

Tests reflected XSS detection. The `/safe-greet` route uses `markupsafe.escape` correctly and must NOT be flagged — exercises the harness's ability to distinguish escaped from unescaped sinks.
