# Sample Report — `trace_Razrusheniye_recovery_live`

> Unified per-sample evidence report with an execution-order timeline and per-loop behavior categorization.

## 1. Identity

| field | value |
|---|---|
| family tag | `razrusheniye` |
| session | `trace_Razrusheniye_recovery_live` |
| execution_quality | **encrypted_complete** |
| recovery tier | **RC_MATCHED** (4/7 RC cases matched) |
| `NO_PAYLOAD_RUN` flag | `False` |
| `VALIDATED` flag | `False` |
| primary cipher | **no cipher identified** |
| key_chain_depth | 21275 |
| runtime_sec | 7.69 |

## 2. Recovery Verdict

- **strict RC checklist (RC-01..RC-07)**: `RC-04`, `RC-05`, `RC-06`, `RC-07`
- **Loop-Based Crypto Behavior Identification**: no (primary cipher = `no cipher identified`)
- **Key Detection** (any of: captured asymmetric private key, memory-residue key, inline symmetric key, hardcoded key, or RNG output): yes
- **File Recoverability**: yes

## 3. Cryptographic Behavior (API trace)

| metric | count | spec/source |
|---|---:|---|
| RNG calls | 21314 | FIPS-140-2 §4.6 (NIST SP 800-90A); MS Learn CNG/CryptoAPI |
| Sym encrypt calls | 170200 | MS Learn BCryptEncrypt; FIPS-197 (AES) |
| Asym blobs captured | 0 | MS Learn BCryptExportKey; PKCS#1 |
| Unique sym keys (chain) | 1 | RFC 5246 / FIPS-197 |
| KDF chain depth | 21275 | RFC 2104 (HMAC) / RFC 5869 (HKDF) |
| Hardcoded-key ratio | 1.00 | RC-04 indicator (Bajpai & Enbody 2020) |

## 4. File Operations

| op | count |
|---|---:|
| writes | 73235 |
| reads | 86326 |
| renames | 0 |
| deletes | 63411 |

## 5. Loop Behavior Category Breakdown

> 14-category classification from Ransack loop classifier, spec-grounded via the loop-pattern and cipher-constant catalogs.

| Category | Clusters | Iter weight | Meaning |
|---|---:|---:|---|
| `fallback` | 5 | 363 | Fallback / unclassified loops (no rule fired — likely benign Windows runtime utility) |
| `control_flow` | 1 | 9 | Control flow dispatch (indirect call, virtual table, jump table) |
| `file_io` | 2 | 7 | Filesystem read/write pair (encrypted file output) |
| `encoding` | 1 | 3 | Encoding / transcoding loops (base64, hex, URL, custom alphabet) |

## 6. Execution-Order Timeline (top 10 scored loops)

> Per-loop scoring weights iteration count, crypto-call density, and classifier confidence.

| rank | score | label | iters | header IP | cluster id | module |
|---:|---:|---|---:|---|---|---|
| 1 | 269 | `unknown.utility` | 269 | `0x7ff6d0341c22` | `b8cc93a30fac` | `razrusheniye.exe` |
| 2 | 38 | `unknown.utility` | 38 | `0x7ff6d03418b0` | `14d9992ba3f7` | `razrusheniye.exe` |
| 3 | 33 | `unknown.utility` | 33 | `0x7ff6d0341b71` | `14d9992ba3f7` | `razrusheniye.exe` |
| 4 | 6 | `fs.read_write_pair` | 3 | `0x7ff6d0341a70` | `77f9e3fcea27` | `razrusheniye.exe` |
| 5 | 6 | `encoding.base64_pack` | 3 | `0x7ff6d0341f72` | `e8fd9b3ddf1d` | `razrusheniye.exe` |
| 6 | 5 | `unknown.utility` | 5 | `0x7ff6d0341bf0` | `ca3ea8cb9f92` | `razrusheniye.exe` |
| 7 | 4 | `fs.read_write_pair` | 2 | `0x7ff6d0341ad0` | `5a6fd2f87e20` | `razrusheniye.exe` |
| 8 | 4 | `anti.short_loop` | 3 | `0x7ff6d0341720` | `a99026232e05` | `razrusheniye.exe` |
| 9 | 4 | `fs.read_write_pair` | 2 | `0x7ff6d0341803` | `5a6fd2f87e20` | `razrusheniye.exe` |
| 10 | 4 | `anti.short_loop` | 3 | `0x7ff6d0341283` | `a99026232e05` | `razrusheniye.exe` |
