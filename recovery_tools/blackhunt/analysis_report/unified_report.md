# Sample Report — `trace_BlackHunt_recovery_live`

> Unified per-sample evidence report with an execution-order timeline and per-loop behavior categorization.

## 1. Identity

| field | value |
|---|---|
| family tag | `blackhunt` |
| session | `trace_BlackHunt_recovery_live` |
| execution_quality | **encrypted_complete** |
| recovery tier | **RC_MATCHED** (5/7 RC cases matched) |
| `NO_PAYLOAD_RUN` flag | `False` |
| `VALIDATED` flag | `False` |
| primary cipher | **ChaCha8 (Conti body)** |
| key_chain_depth | 6 |
| runtime_sec | 0.93 |

## 2. Recovery Verdict

- **strict RC checklist (RC-01..RC-07)**: `RC-01`, `RC-02`, `RC-03`, `RC-06`, `RC-07`
- **Loop-Based Crypto Behavior Identification**: yes (primary cipher = `ChaCha8 (Conti body)`)
- **Key Detection** (any of: captured asymmetric private key, memory-residue key, inline symmetric key, hardcoded key, or RNG output): yes
- **File Recoverability**: yes

## 3. Cryptographic Behavior (API trace)

| metric | count | spec/source |
|---|---:|---|
| RNG calls | 41866 | FIPS-140-2 §4.6 (NIST SP 800-90A); MS Learn CNG/CryptoAPI |
| Sym encrypt calls | 41895 | MS Learn BCryptEncrypt; FIPS-197 (AES) |
| Asym blobs captured | 0 | MS Learn BCryptExportKey; PKCS#1 |
| Unique sym keys (chain) | 0 | RFC 5246 / FIPS-197 |
| KDF chain depth | 6 | RFC 2104 (HMAC) / RFC 5869 (HKDF) |
| Hardcoded-key ratio | 0.00 | RC-04 indicator (Bajpai & Enbody 2020) |

## 4. File Operations

| op | count |
|---|---:|
| writes | 502008 |
| reads | 39795 |
| renames | 6820 |
| deletes | 51 |

## 5. Loop Behavior Category Breakdown

> 14-category classification from Ransack loop classifier, spec-grounded via the loop-pattern and cipher-constant catalogs.

| Category | Clusters | Iter weight | Meaning |
|---|---:|---:|---|
| `control_flow` | 13 | 116 | Control flow dispatch (indirect call, virtual table, jump table) |
| `fallback` | 13 | 43 | Fallback / unclassified loops (no rule fired — likely benign Windows runtime utility) |
| `file_io` | 17 | 42 | Filesystem read/write pair (encrypted file output) |
| `crypto` | 3 | 11 | Crypto-labelled loops (AES round/sbox, ChaCha quarter, XOR stream/chain, TEA round, hash compress) |

## 6. Execution-Order Timeline (top 10 scored loops)

> Per-loop scoring weights iteration count, crypto-call density, and classifier confidence.

| rank | score | label | iters | header IP | cluster id | module |
|---:|---:|---|---:|---|---|---|
| 1 | 15 | `crypto.crc32_table` | 3 | `0xba1254` | `de62cf863783` | `blackhunt_1.exe` |
| 2 | 15 | `crypto.crc32_table` | 3 | `0xba1254` | `de62cf863783` | `blackhunt_1.exe` |
| 3 | 12 | `crypto.xor_rotate` | 3 | `0xba20a0` | `1868de680b0e` | `blackhunt_1.exe` |
| 4 | 7 | `crypto.xor_stream` | 2 | `0xbaa60b` | `eb80345d293b` | `blackhunt_1.exe` |
| 5 | 6 | `counter.cmp_jb_walk` | 3 | `0xba1fd6` | `f98c474d8b44` | `blackhunt_1.exe` |
| 6 | 6 | `fs.read_write_pair` | 3 | `0xba1b19` | `edb4faeb5689` | `blackhunt_1.exe` |
| 7 | 6 | `fs.read_write_pair` | 3 | `0xba29c4` | `2063bd93d0dc` | `blackhunt_1.exe` |
| 8 | 6 | `fs.read_write_pair` | 3 | `0xbaf114` | `3a0e86ac3086` | `blackhunt_1.exe` |
| 9 | 6 | `counter.cmp_jb_walk` | 3 | `0xba36f0` | `234a1e849756` | `blackhunt_1.exe` |
| 10 | 6 | `counter.cmp_jb_walk` | 3 | `0xba3720` | `234a1e849756` | `blackhunt_1.exe` |
