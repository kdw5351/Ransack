# Sample Report — `trace_AzzaSec_recovery_live`

> Unified per-sample evidence report with an execution-order timeline and per-loop behavior categorization.

## 1. Identity

| field | value |
|---|---|
| family tag | `azzasec` |
| session | `trace_AzzaSec_recovery_live` |
| execution_quality | **pin_attach_failed** |
| recovery tier | **NO_PAYLOAD_RUN** (0/7 RC cases matched) |
| `NO_PAYLOAD_RUN` flag | `True` |
| `VALIDATED` flag | `False` |
| primary cipher | **no cipher identified** |
| key_chain_depth | 0 |
| runtime_sec | ? |

## 2. Recovery Verdict

- **strict RC checklist (RC-01..RC-07)**: `(none fired)` — falls into the confident no-match bucket
- **Loop-Based Crypto Behavior Identification**: no (primary cipher = `no cipher identified`)
- **Key Detection** (any of: captured asymmetric private key, memory-residue key, inline symmetric key, hardcoded key, or RNG output): no
- **File Recoverability**: no

## 3. Cryptographic Behavior (API trace)

| metric | count | spec/source |
|---|---:|---|
| RNG calls | 0 | FIPS-140-2 §4.6 (NIST SP 800-90A); MS Learn CNG/CryptoAPI |
| Sym encrypt calls | 0 | MS Learn BCryptEncrypt; FIPS-197 (AES) |
| Asym blobs captured | 0 | MS Learn BCryptExportKey; PKCS#1 |
| Unique sym keys (chain) | 0 | RFC 5246 / FIPS-197 |
| KDF chain depth | 0 | RFC 2104 (HMAC) / RFC 5869 (HKDF) |
| Hardcoded-key ratio | 0.00 | RC-04 indicator (Bajpai & Enbody 2020) |

## 4. File Operations

| op | count |
|---|---:|
| writes | 0 |
| reads | 0 |
| renames | 0 |
| deletes | 0 |

## 5. Loop Behavior Category Breakdown

> 14-category classification from Ransack loop classifier, spec-grounded via the loop-pattern and cipher-constant catalogs.

| Category | Clusters | Iter weight | Meaning |
|---|---:|---:|---|

## 6. Execution-Order Timeline (top 10 scored loops)

> Per-loop scoring weights iteration count, crypto-call density, and classifier confidence.

| rank | score | label | iters | header IP | cluster id | module |
|---:|---:|---|---:|---|---|---|
