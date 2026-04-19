# hardcoded_secret

Tests detection of secrets in source. semgrep auto-config catches this; in Phase 2, gitleaks will too. The harness should NOT also flag the postgres URL (it's a non-secret default credential string).
