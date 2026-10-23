# Sample Report — `trace_KillRabbit_recovery_live`

> Unified per-sample evidence report with an execution-order timeline and per-loop behavior categorization.

## 1. Identity

| field | value |
|---|---|
| family tag | `killrabbit` |
| session | `trace_KillRabbit_recovery_live` |
| execution_quality | **encrypted_complete** |
| recovery tier | **RC_MATCHED** (3/7 RC cases matched) |
| `NO_PAYLOAD_RUN` flag | `False` |
| `VALIDATED` flag | `False` |
| primary cipher | **AES-256-CBC** |
| key_chain_depth | 131 |
| runtime_sec | 1.85 |

## 2. Recovery Verdict

- **strict RC checklist (RC-01..RC-07)**: `RC-04`, `RC-06`, `RC-07`
- **Loop-Based Crypto Behavior Identification**: yes (primary cipher = `AES-256-CBC`)
- **Key Detection** (any of: captured asymmetric private key, memory-residue key, inline symmetric key, hardcoded key, or RNG output): yes
- **File Recoverability**: yes

## 3. Cryptographic Behavior (API trace)

| metric | count | spec/source |
|---|---:|---|
| RNG calls | 44 | FIPS-140-2 §4.6 (NIST SP 800-90A); MS Learn CNG/CryptoAPI |
| Sym encrypt calls | 504 | MS Learn BCryptEncrypt; FIPS-197 (AES) |
| Asym blobs captured | 0 | MS Learn BCryptExportKey; PKCS#1 |
| Unique sym keys (chain) | 1 | RFC 5246 / FIPS-197 |
| KDF chain depth | 131 | RFC 2104 (HMAC) / RFC 5869 (HKDF) |
| Hardcoded-key ratio | 1.00 | RC-04 indicator (Bajpai & Enbody 2020) |

## 4. File Operations

| op | count |
|---|---:|
| writes | 483 |
| reads | 1845 |
| renames | 0 |
| deletes | 88 |

## 5. Loop Behavior Category Breakdown

> 14-category classification from Ransack loop classifier, spec-grounded via the loop-pattern and cipher-constant catalogs.

| Category | Clusters | Iter weight | Meaning |
|---|---:|---:|---|
| `fallback` | 118 | 109079 | Fallback / unclassified loops (no rule fired — likely benign Windows runtime utility) |
| `file_io` | 186 | 10460 | Filesystem read/write pair (encrypted file output) |
| `control_flow` | 54 | 3116 | Control flow dispatch (indirect call, virtual table, jump table) |
| `crypto` | 38 | 2792 | Crypto-labelled loops (AES round/sbox, ChaCha quarter, XOR stream/chain, TEA round, hash compress) |
| `memory_scan` | 1 | 128 | Memory-scanning loops (search a region for a pattern or marker) |

## 6. Execution-Order Timeline (top 10 scored loops)

> Per-loop scoring weights iteration count, crypto-call density, and classifier confidence.

| rank | score | label | iters | header IP | cluster id | module |
|---:|---:|---|---:|---|---|---|
| 1 | 85661 | `unknown.utility` | 85661 | `0xdf5d37` | `208d13e34ce0` | `killrabbit.exe` |
| 2 | 9448 | `unknown.utility` | 9448 | `0xdfe4e5` | `e09741e34031` | `killrabbit.exe` |
| 3 | 3129 | `unknown.utility` | 3129 | `0xdfa384` | `b60c522e1c15` | `killrabbit.exe` |
| 4 | 2068 | `counter.cmp_jb_walk` | 1034 | `0xdfa2c1` | `0d711b77a120` | `killrabbit.exe` |
| 5 | 1972 | `crypto.bignum_modexp` | 519 | `0xdfa320` | `14371a2bd88c` | `killrabbit.exe` |
| 6 | 1904 | `fs.read_write_pair` | 907 | `0xdfa400` | `b73a14cfe5d3` | `killrabbit.exe` |
| 7 | 1881 | `unknown.utility` | 1881 | `0xdfec53` | `0af419e52a6a` | `killrabbit.exe` |
| 8 | 1812 | `fs.read_write_pair` | 863 | `0xdfe390` | `ba855ab725c9` | `killrabbit.exe` |
| 9 | 1808 | `fs.read_write_pair` | 861 | `0xdfe38d` | `d46a8ec26a97` | `killrabbit.exe` |
| 10 | 1562 | `counter.cmp_jb_walk` | 781 | `0xdfa2c1` | `0d711b77a120` | `killrabbit.exe` |
