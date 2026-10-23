# Crypt888 reproduction note

- cipher: DES-CBC, IV=0, PKCS#7
- key: MD5("888")[:8] = 0a113ef6b61820da (build-fixed)
- rename: Lock.<original>

The key is derived from a 3-byte hardcoded seed, so recovery is universal
for this build and needs no per-victim secret.
