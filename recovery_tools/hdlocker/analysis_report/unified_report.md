# Sample Report — `trace_HDLocker_recovery_live`

> Unified per-sample evidence report with an execution-order timeline and per-loop behavior categorization.

## 1. Identity

| field | value |
|---|---|
| family tag | `hdlocker` |
| session | `trace_HDLocker_recovery_live` |
| execution_quality | **encrypted_partial** |
| recovery tier | **RC_MATCHED** (1/7 RC cases matched) |
| `NO_PAYLOAD_RUN` flag | `False` |
| `VALIDATED` flag | `False` |
| primary cipher | **TEA (16-round; decisive constant tea_delta)** |
| key_chain_depth | 0 |
| runtime_sec | 396 |

## 2. Recovery Verdict

- **strict RC checklist (RC-01..RC-07)**: `RC-06`
- **Loop-Based Crypto Behavior Identification**: yes (primary cipher = `TEA (16-round; decisive constant tea_delta)`)
- **Key Detection** (any of: captured asymmetric private key, memory-residue key, inline symmetric key, hardcoded key, or RNG output): no
- **File Recoverability**: yes

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
| writes | 93172 |
| reads | 40108 |
| renames | 9891 |
| deletes | 0 |

## 5. Loop Behavior Category Breakdown

> 14-category classification from Ransack loop classifier, spec-grounded via the loop-pattern and cipher-constant catalogs.

| Category | Clusters | Iter weight | Meaning |
|---|---:|---:|---|
| `crypto` | 285 | 784 | Crypto-labelled loops (AES round/sbox, ChaCha quarter, XOR stream/chain, TEA round, hash compress) |
| `fallback` | 6 | 20 | Fallback / unclassified loops (no rule fired — likely benign Windows runtime utility) |
| `control_flow` | 6 | 16 | Control flow dispatch (indirect call, virtual table, jump table) |
| `file_io` | 2 | 4 | Filesystem read/write pair (encrypted file output) |

## 6. Execution-Order Timeline (top 10 scored loops)

> Per-loop scoring weights iteration count, crypto-call density, and classifier confidence.

| rank | score | label | iters | header IP | cluster id | module |
|---:|---:|---|---:|---|---|---|
| 1 | 38 | `crypto.aes_software_sbox` | 8 | `0x118523` | `df5d1eb9c8f7` | `hdlocker.exe` |
| 2 | 33 | `crypto.aes_mixcolumns` | 7 | `0x121b55` | `4173e59670ea` | `hdlocker.exe` |
| 3 | 31 | `crypto.sha2_round` | 6 | `0xeb34d` | `85adc3b308af` | `hdlocker.exe` |
| 4 | 26 | `crypto.sha2_round` | 5 | `0x1540e9` | `ca1839a977f1` | `hdlocker.exe` |
| 5 | 24 | `crypto.aes_mixcolumns` | 5 | `0x163e33` | `a2099ee0ca9e` | `hdlocker.exe` |
| 6 | 24 | `crypto.aes_mixcolumns` | 5 | `0xd7039` | `566fca2aa27a` | `hdlocker.exe` |
| 7 | 20 | `crypto.sha2_round` | 4 | `0x15e335` | `e74ef85c9f62` | `hdlocker.exe` |
| 8 | 20 | `crypto.sha2_round` | 4 | `0x1215c2` | `b5b5318afe0c` | `hdlocker.exe` |
| 9 | 19 | `crypto.aes_mixcolumns` | 4 | `0xea661` | `827ba88232c2` | `hdlocker.exe` |
| 10 | 19 | `crypto.aes_mixcolumns` | 4 | `0x1462ff` | `df0ac40f8396` | `hdlocker.exe` |
