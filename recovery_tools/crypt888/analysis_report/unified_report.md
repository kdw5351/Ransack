# Sample Report — `trace_Crypt888_recovery_live`

> Unified per-sample evidence report with an execution-order timeline and per-loop behavior categorization.

## 1. Identity

| field | value |
|---|---|
| family tag | `crypt888` |
| session | `trace_Crypt888_recovery_live` |
| execution_quality | **encrypted_complete** |
| recovery tier | **RC_MATCHED** (2/7 RC cases matched) |
| `NO_PAYLOAD_RUN` flag | `False` |
| `VALIDATED` flag | `False` |
| primary cipher | **XOR (stream) (heuristic, unconfirmed)** |
| key_chain_depth | 99 |
| runtime_sec | 107.31 |

## 2. Recovery Verdict

- **strict RC checklist (RC-01..RC-07)**: `RC-04`, `RC-07`
- **Loop-Based Crypto Behavior Identification**: yes (primary cipher = `XOR (stream) (heuristic, unconfirmed)`)
- **Key Detection** (any of: captured asymmetric private key, memory-residue key, inline symmetric key, hardcoded key, or RNG output): yes
- **File Recoverability**: yes

## 3. Cryptographic Behavior (API trace)

| metric | count | spec/source |
|---|---:|---|
| RNG calls | 53 | FIPS-140-2 §4.6 (NIST SP 800-90A); MS Learn CNG/CryptoAPI |
| Sym encrypt calls | 576 | MS Learn BCryptEncrypt; FIPS-197 (AES) |
| Asym blobs captured | 0 | MS Learn BCryptExportKey; PKCS#1 |
| Unique sym keys (chain) | 1 | RFC 5246 / FIPS-197 |
| KDF chain depth | 99 | RFC 2104 (HMAC) / RFC 5869 (HKDF) |
| Hardcoded-key ratio | 1.00 | RC-04 indicator (Bajpai & Enbody 2020) |

## 4. File Operations

| op | count |
|---|---:|
| writes | 230 |
| reads | 1483 |
| renames | 0 |
| deletes | 108 |

## 5. Loop Behavior Category Breakdown

> 14-category classification from Ransack loop classifier, spec-grounded via the loop-pattern and cipher-constant catalogs.

| Category | Clusters | Iter weight | Meaning |
|---|---:|---:|---|
| `fallback` | 6 | 19 | Fallback / unclassified loops (no rule fired — likely benign Windows runtime utility) |
| `control_flow` | 6 | 15 | Control flow dispatch (indirect call, virtual table, jump table) |
| `file_io` | 3 | 7 | Filesystem read/write pair (encrypted file output) |
| `crypto` | 2 | 7 | Crypto-labelled loops (AES round/sbox, ChaCha quarter, XOR stream/chain, TEA round, hash compress) |
| `memory_pack` | 1 | 3 | Memory pack/unpack & bit-shuffle (packer stub, struct serialisation) |

## 6. Execution-Order Timeline (top 10 scored loops)

> Per-loop scoring weights iteration count, crypto-call density, and classifier confidence.

| rank | score | label | iters | header IP | cluster id | module |
|---:|---:|---|---:|---|---|---|
| 1 | 11 | `crypto.xor_stream` | 3 | `0x41f3a5` | `c6d73c58bf09` | `crypt888.exe` |
| 2 | 7 | `crypto.xor_stream` | 2 | `0x41ef38` | `2bc3c5a00a2d` | `crypt888.exe` |
| 3 | 7 | `unknown.utility` | 7 | `0x41899a` | `02b879fa22fc` | `crypt888.exe` |
| 4 | 7 | `crypto.xor_stream` | 2 | `0x41f3a5` | `c6d73c58bf09` | `crypt888.exe` |
| 5 | 6 | `fs.read_write_pair` | 3 | `0x417595` | `5d9d0d153e25` | `crypt888.exe` |
| 6 | 6 | `memory.bitfield_assemble` | 3 | `0x41aae7` | `e9b47097af67` | `crypt888.exe` |
| 7 | 4 | `fs.read_write_pair` | 2 | `0x41f2fb` | `c1b4888d574e` | `crypt888.exe` |
| 8 | 4 | `anti.short_loop` | 3 | `0x4153f9` | `2a32f162099a` | `crypt888.exe` |
| 9 | 4 | `fs.read_write_pair` | 2 | `0x41ac36` | `de113af493a7` | `crypt888.exe` |
| 10 | 4 | `anti.short_loop` | 3 | `0x41f59e` | `b4b1cbf3a8d7` | `crypt888.exe` |
