# jwt_no_verify

Held-out test task. JWT decoded with `verify=False` (PyJWT 1.x style) /
`options={"verify_signature": False}` (PyJWT 2.x style). CWE-347 (Improper
Verification of Cryptographic Signature) — anyone can forge a token
because the signature is never checked.

semgrep covers the PyJWT pattern. Whether the LLM correctly upgrades
severity to **critical** for an auth bypass is the interesting signal.
