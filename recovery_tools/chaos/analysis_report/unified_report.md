# Sample Report — `trace_chaos`

> Unified per-sample evidence report with an execution-order timeline and per-loop behavior categorization.

## 1. Identity

| field | value |
|---|---|
| family tag | `chaos` |
| session | `trace_chaos` |
| execution_quality | **encrypted_complete** |
| recovery tier | **RC_MATCHED** (1/7 RC cases matched) |
| `NO_PAYLOAD_RUN` flag | `False` |
| `VALIDATED` flag | `False` |
| primary cipher | **no cipher identified** |
| key_chain_depth | 2792 |
| runtime_sec | 205.92 |

## 2. Recovery Verdict

- **strict RC checklist (RC-01..RC-07)**: `RC-07`
- **Loop-Based Crypto Behavior Identification**: no (primary cipher = `no cipher identified`)
- **Key Detection** (any of: captured asymmetric private key, memory-residue key, inline symmetric key, hardcoded key, or RNG output): yes
- **File Recoverability**: yes

## 3. Cryptographic Behavior (API trace)

| metric | count | spec/source |
|---|---:|---|
| RNG calls | 688302 | FIPS-140-2 §4.6 (NIST SP 800-90A); MS Learn CNG/CryptoAPI |
| Sym encrypt calls | 34632 | MS Learn BCryptEncrypt; FIPS-197 (AES) |
| Asym blobs captured | 0 | MS Learn BCryptExportKey; PKCS#1 |
| Unique sym keys (chain) | 0 | RFC 5246 / FIPS-197 |
| KDF chain depth | 2792 | RFC 2104 (HMAC) / RFC 5869 (HKDF) |
| Hardcoded-key ratio | 0.67 | RC-04 indicator (Bajpai & Enbody 2020) |

## 4. File Operations

| op | count |
|---|---:|
| writes | 103131 |
| reads | 48321 |
| renames | 16061 |
| deletes | 0 |

## 5. Loop Behavior Category Breakdown

> 14-category classification from Ransack loop classifier, spec-grounded via the loop-pattern and cipher-constant catalogs.

| Category | Clusters | Iter weight | Meaning |
|---|---:|---:|---|
| `file_io` | 3 | 7 | Filesystem read/write pair (encrypted file output) |
| `fallback` | 2 | 4 | Fallback / unclassified loops (no rule fired — likely benign Windows runtime utility) |

## 6. Execution-Order Timeline (top 10 scored loops)

> Per-loop scoring weights iteration count, crypto-call density, and classifier confidence.

| rank | score | label | iters | header IP | cluster id | module |
|---:|---:|---|---:|---|---|---|
| 1 | 6 | `fs.read_write_pair` | 3 | `0x7ffb30313c99` | `a1bfca200813` | `unknown` |
| 2 | 4 | `fs.read_write_pair` | 2 | `0x7ffb303130a0` | `299e24be3159` | `unknown` |
| 3 | 4 | `fs.read_write_pair` | 2 | `0x7ffb303131f7` | `4cdce99a8dd9` | `unknown` |
| 4 | 2 | `unknown.utility` | 2 | `0x7ffb303104c0` | `f36071bacae4` | `unknown` |
| 5 | 2 | `unknown.utility` | 2 | `0x7ffb30313324` | `a6deeec77545` | `unknown` |
