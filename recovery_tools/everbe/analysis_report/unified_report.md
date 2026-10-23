# Sample Report — `trace_Everbe_recovery_live`

> Unified per-sample evidence report with an execution-order timeline and per-loop behavior categorization.

## 1. Identity

| field | value |
|---|---|
| family tag | `everbe` |
| session | `trace_Everbe_recovery_live` |
| execution_quality | **indeterminate** |
| recovery tier | **INFEASIBLE** (0/7 RC cases matched) |
| `NO_PAYLOAD_RUN` flag | `False` |
| `VALIDATED` flag | `False` |
| primary cipher | **AES NI (heuristic, unconfirmed)** |
| key_chain_depth | 0 |
| runtime_sec | 37.31 |

## 2. Recovery Verdict

- **strict RC checklist (RC-01..RC-07)**: `(none fired)` — falls into the confident no-match bucket
- **Loop-Based Crypto Behavior Identification**: yes (primary cipher = `AES NI (heuristic, unconfirmed)`)
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
| writes | 6006 |
| reads | 3342 |
| renames | 1114 |
| deletes | 0 |

## 5. Loop Behavior Category Breakdown

> 14-category classification from Ransack loop classifier, spec-grounded via the loop-pattern and cipher-constant catalogs.

| Category | Clusters | Iter weight | Meaning |
|---|---:|---:|---|
| `fallback` | 24 | 60 | Fallback / unclassified loops (no rule fired — likely benign Windows runtime utility) |
| `file_io` | 11 | 25 | Filesystem read/write pair (encrypted file output) |
| `crypto` | 5 | 14 | Crypto-labelled loops (AES round/sbox, ChaCha quarter, XOR stream/chain, TEA round, hash compress) |
| `anti_forensic` | 2 | 5 | Anti-forensic loops (secure-wipe, shadow-copy deletion, log clearing) |
| `control_flow` | 2 | 5 | Control flow dispatch (indirect call, virtual table, jump table) |
| `encoding` | 1 | 3 | Encoding / transcoding loops (base64, hex, URL, custom alphabet) |
| `memory_copy` | 1 | 3 | Memory copy / move primitives (memcpy, RtlMoveMemory) |

## 6. Execution-Order Timeline (top 10 scored loops)

> Per-loop scoring weights iteration count, crypto-call density, and classifier confidence.

| rank | score | label | iters | header IP | cluster id | module |
|---:|---:|---|---:|---|---|---|
| 1 | 17 | `crypto.aes_ni` | 3 | `0x7ff6ba1f9d52` | `5a15a0ff7d26` | `everbe.exe` |
| 2 | 17 | `crypto.aes_ni` | 3 | `0x7ff6ba1f9bce` | `0c2ec496d8fd` | `everbe.exe` |
| 3 | 14 | `crypto.aes_mixcolumns` | 3 | `0x7ff6ba1e69b8` | `8f3020c939f1` | `everbe.exe` |
| 4 | 11 | `crypto.xor_stream` | 3 | `0x7ff6ba1e6b4f` | `62064de61b3d` | `everbe.exe` |
| 5 | 8 | `fs.read_write_pair` | 4 | `0x7ff6ba1e6d02` | `9eac5491efe7` | `everbe.exe` |
| 6 | 8 | `memory.bulk_movups_sse` | 3 | `0x7ff6ba1ea020` | `60a568e70657` | `everbe.exe` |
| 7 | 7 | `crypto.xor_stream` | 2 | `0x7ff6ba1f9a44` | `812f242a3fb9` | `everbe.exe` |
| 8 | 6 | `shred.random_overwrite` | 3 | `0x7ff6ba1e323d` | `383902771cb7` | `everbe.exe` |
| 9 | 6 | `fs.read_write_pair` | 3 | `0x7ff6ba1e13b0` | `45a6b1805b31` | `everbe.exe` |
| 10 | 6 | `counter.cmp_jb_walk` | 3 | `0x7ff6ba1e8d62` | `a9ef42eb61c9` | `everbe.exe` |
