# weak_crypto_md5

Password hashing implemented with `hashlib.md5(...).hexdigest()`. CWE-327
(Use of a Broken or Risky Cryptographic Algorithm) — MD5 is fast, no salt,
and trivially rainbow-tabled.

bandit's B324 should catch the `hashlib.md5` call directly. Tests whether
the harness escalates the default LOW/MEDIUM severity to **high**, given
the function name `hash_password` makes the security context obvious.
