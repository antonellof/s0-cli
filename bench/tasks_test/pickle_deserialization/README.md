# pickle_deserialization

Held-out test task. Loads a pickle blob from a base64-encoded query string
and `pickle.loads` it directly. CWE-502 — pickle deserialization is
arbitrary code execution by design (`__reduce__`).

bandit (B301) should catch the `pickle.loads` call. Slightly different
data flow than `yaml_unsafe_load` so it tests whether the harness's vibe
detector generalizes beyond the train set.
