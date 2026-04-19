# yaml_unsafe_load

Loads YAML config from disk with `yaml.load(...)` (no `Loader=`), which is
equivalent to `yaml.UnsafeLoader` and lets a malicious file execute
arbitrary Python via `!!python/object/apply:os.system`. CWE-502
(Deserialization of Untrusted Data).

Both bandit (B506) and semgrep should catch it. Tests whether the LLM
suggests `yaml.safe_load` as the fix.
