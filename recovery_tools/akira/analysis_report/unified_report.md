# Sample Report — `trace_Akira_recovery_live`

> Unified per-sample evidence report with an execution-order timeline and per-loop behavior categorization.

## 1. Identity

| field | value |
|---|---|
| family tag | `akira` |
| session | `trace_Akira_recovery_live` |
| execution_quality | **encrypted_complete** |
| recovery tier | **RC_MATCHED** (1/7 RC cases matched) |
| `NO_PAYLOAD_RUN` flag | `False` |
| `VALIDATED` flag | `False` |
| primary cipher | **XOR (rotate) (heuristic, unconfirmed)** |
| key_chain_depth | 23 |
| runtime_sec | 59.53 |

## 2. Recovery Verdict

- **strict RC checklist (RC-01..RC-07)**: `RC-07`
- **Loop-Based Crypto Behavior Identification**: yes (primary cipher = `XOR (rotate) (heuristic, unconfirmed)`)
- **Key Detection** (any of: captured asymmetric private key, memory-residue key, inline symmetric key, hardcoded key, or RNG output): yes
- **File Recoverability**: yes

## 3. Cryptographic Behavior (API trace)

| metric | count | spec/source |
|---|---:|---|
| RNG calls | 7 | FIPS-140-2 §4.6 (NIST SP 800-90A); MS Learn CNG/CryptoAPI |
| Sym encrypt calls | 6 | MS Learn BCryptEncrypt; FIPS-197 (AES) |
| Asym blobs captured | 0 | MS Learn BCryptExportKey; PKCS#1 |
| Unique sym keys (chain) | 0 | RFC 5246 / FIPS-197 |
| KDF chain depth | 23 | RFC 2104 (HMAC) / RFC 5869 (HKDF) |
| Hardcoded-key ratio | 1.00 | RC-04 indicator (Bajpai & Enbody 2020) |

## 4. File Operations

| op | count |
|---|---:|
| writes | 50057 |
| reads | 29196 |
| renames | 11150 |
| deletes | 0 |

## 5. Loop Behavior Category Breakdown

> 14-category classification from Ransack loop classifier, spec-grounded via the loop-pattern and cipher-constant catalogs.

| Category | Clusters | Iter weight | Meaning |
|---|---:|---:|---|
| `fallback` | 45 | 209 | Fallback / unclassified loops (no rule fired — likely benign Windows runtime utility) |
| `file_io` | 24 | 75 | Filesystem read/write pair (encrypted file output) |
| `control_flow` | 4 | 33 | Control flow dispatch (indirect call, virtual table, jump table) |
| `crypto` | 7 | 22 | Crypto-labelled loops (AES round/sbox, ChaCha quarter, XOR stream/chain, TEA round, hash compress) |
| `memory_copy` | 5 | 18 | Memory copy / move primitives (memcpy, RtlMoveMemory) |

## 6. Execution-Order Timeline (top 10 scored loops)

> Per-loop scoring weights iteration count, crypto-call density, and classifier confidence.

| rank | score | label | iters | header IP | cluster id | module |
|---:|---:|---|---:|---|---|---|
| 1 | 12 | `crypto.xor_rotate` | 3 | `0x7ff7a5db93b0` | `869ea272937f` | `akira.exe` |
| 2 | 12 | `crypto.xor_rotate` | 3 | `0x7ff7a5db92f0` | `a6efe18c32b4` | `akira.exe` |
| 3 | 12 | `crypto.xor_rotate` | 3 | `0x7ff7a5db93b0` | `869ea272937f` | `akira.exe` |
| 4 | 12 | `crypto.xor_rotate` | 3 | `0x7ff7a5db92f0` | `a6efe18c32b4` | `akira.exe` |
| 5 | 9 | `crypto.aes_mixcolumns` | 2 | `0x7ff7a5dcb940` | `ddd9540e22e5` | `akira.exe` |
| 6 | 9 | `crypto.aes_mixcolumns` | 2 | `0x7ff7a5dcb7c0` | `1f12634adf41` | `akira.exe` |
| 7 | 8 | `memory.bulk_movups_sse` | 3 | `0x7ff7a5dffda0` | `378f05e33525` | `akira.exe` |
| 8 | 8 | `fs.read_write_pair` | 4 | `0x7ff7a5de8a31` | `2e936ff9c17d` | `akira.exe` |
| 9 | 8 | `fs.read_write_pair` | 4 | `0x7ff7a5dc9c70` | `afdd9d2dc2f8` | `akira.exe` |
| 10 | 8 | `memory.bulk_movups_sse` | 3 | `0x7ff7a5dffda0` | `378f05e33525` | `akira.exe` |
