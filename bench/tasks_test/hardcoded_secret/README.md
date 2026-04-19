# hardcoded_secret

Held-out test task. Tests detection of secrets in source. Both semgrep
(auto config) and gitleaks should catch the AWS key. The harness should
NOT also flag the postgres URL (it's a non-secret default credential
string used as a config placeholder, CWE-798 doesn't apply).
