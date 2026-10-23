# Sample Report — `trace_WannaCry_recovery_live`

> Unified per-sample evidence report with an execution-order timeline and per-loop behavior categorization.

## 1. Identity

| field | value |
|---|---|
| family tag | `wannacry` |
| session | `trace_WannaCry_recovery_live` |
| execution_quality | **encrypted_complete** |
| recovery tier | **RC_MATCHED** (4/7 RC cases matched) |
| `NO_PAYLOAD_RUN` flag | `False` |
| `VALIDATED` flag | `False` |
| primary cipher | **AES (S-box, software) (heuristic, unconfirmed)** |
| key_chain_depth | 31 |
| runtime_sec | 1.42 |

## 2. Recovery Verdict

- **strict RC checklist (RC-01..RC-07)**: `RC-01`, `RC-02`, `RC-03`, `RC-06`
- **Loop-Based Crypto Behavior Identification**: yes (primary cipher = `AES (S-box, software) (heuristic, unconfirmed)`)
- **Key Detection** (any of: captured asymmetric private key, memory-residue key, inline symmetric key, hardcoded key, or RNG output): yes
- **File Recoverability**: yes

## 3. Cryptographic Behavior (API trace)

| metric | count | spec/source |
|---|---:|---|
| RNG calls | 5120 | FIPS-140-2 §4.6 (NIST SP 800-90A); MS Learn CNG/CryptoAPI |
| Sym encrypt calls | 10246 | MS Learn BCryptEncrypt; FIPS-197 (AES) |
| Asym blobs captured | 0 | MS Learn BCryptExportKey; PKCS#1 |
| Unique sym keys (chain) | 0 | RFC 5246 / FIPS-197 |
| KDF chain depth | 31 | RFC 2104 (HMAC) / RFC 5869 (HKDF) |
| Hardcoded-key ratio | 0.46 | RC-04 indicator (Bajpai & Enbody 2020) |

## 4. File Operations

| op | count |
|---|---:|
| writes | 23888 |
| reads | 7684 |
| renames | 7371 |
| deletes | 44485 |

## 5. Loop Behavior Category Breakdown

> 14-category classification from Ransack loop classifier, spec-grounded via the loop-pattern and cipher-constant catalogs.

| Category | Clusters | Iter weight | Meaning |
|---|---:|---:|---|
| `fallback` | 53 | 61664 | Fallback / unclassified loops (no rule fired — likely benign Windows runtime utility) |
| `crypto` | 17 | 4192 | Crypto-labelled loops (AES round/sbox, ChaCha quarter, XOR stream/chain, TEA round, hash compress) |
| `encoding` | 10 | 370 | Encoding / transcoding loops (base64, hex, URL, custom alphabet) |
| `control_flow` | 14 | 369 | Control flow dispatch (indirect call, virtual table, jump table) |
| `file_io` | 13 | 35 | Filesystem read/write pair (encrypted file output) |

## 6. Execution-Order Timeline (top 10 scored loops)

> Per-loop scoring weights iteration count, crypto-call density, and classifier confidence.

| rank | score | label | iters | header IP | cluster id | module |
|---:|---:|---|---:|---|---|---|
| 1 | 59675 | `unknown.utility` | 59675 | `0x40534b` | `284307f160e7` | `wannacry3.exe` |
| 2 | 19656 | `crypto.aes_software_sbox` | 4095 | `0x40544a` | `0a7911629d20` | `wannacry3.exe` |
| 3 | 731 | `unknown.utility` | 731 | `0x404002` | `187fa108b725` | `wannacry3.exe` |
| 4 | 608 | `counter.cmp_jb_walk` | 304 | `0x404d29` | `6f583d7189e7` | `wannacry3.exe` |
| 5 | 554 | `encoding.base64_pack` | 264 | `0x4051a4` | `75df8fadadb1` | `wannacry3.exe` |
| 6 | 539 | `unknown.utility` | 539 | `0x40489e` | `eb8ad88c50cd` | `wannacry3.exe` |
| 7 | 242 | `unknown.utility` | 242 | `0x405332` | `77f518e09e15` | `wannacry3.exe` |
| 8 | 155 | `unknown.utility` | 155 | `0x14262df8` | `e3c8cd866dd1` | `unknown` |
| 9 | 120 | `crypto.aes_mixcolumns` | 25 | `0x404dae` | `993daad63a5f` | `wannacry3.exe` |
| 10 | 87 | `unknown.utility` | 87 | `0x4051a4` | `5553c0da5bb3` | `wannacry3.exe` |
