# Sample Report — `trace_makop`

> Unified per-sample evidence report with an execution-order timeline and per-loop behavior categorization.

## 1. Identity

| field | value |
|---|---|
| family tag | `makop` |
| session | `trace_makop` |
| execution_quality | **encrypted_complete** |
| recovery tier | **RC_MATCHED** (3/7 RC cases matched) |
| `NO_PAYLOAD_RUN` flag | `False` |
| `VALIDATED` flag | `False` |
| primary cipher | **no cipher identified** |
| key_chain_depth | 20648 |
| runtime_sec | ? |

## 2. Recovery Verdict

- **strict RC checklist (RC-01..RC-07)**: `RC-05`, `RC-06`, `RC-07`
- **Loop-Based Crypto Behavior Identification**: no (primary cipher = `no cipher identified`)
- **Key Detection** (any of: captured asymmetric private key, memory-residue key, inline symmetric key, hardcoded key, or RNG output): yes
- **File Recoverability**: yes

## 3. Cryptographic Behavior (API trace)

| metric | count | spec/source |
|---|---:|---|
| RNG calls | 20659 | FIPS-140-2 §4.6 (NIST SP 800-90A); MS Learn CNG/CryptoAPI |
| Sym encrypt calls | 82608 | MS Learn BCryptEncrypt; FIPS-197 (AES) |
| Asym blobs captured | 0 | MS Learn BCryptExportKey; PKCS#1 |
| Unique sym keys (chain) | 1 | RFC 5246 / FIPS-197 |
| KDF chain depth | 20648 | RFC 2104 (HMAC) / RFC 5869 (HKDF) |
| Hardcoded-key ratio | 0.03 | RC-04 indicator (Bajpai & Enbody 2020) |

## 4. File Operations

| op | count |
|---|---:|
| writes | 201544 |
| reads | 40708 |
| renames | 6782 |
| deletes | 0 |

## 5. Loop Behavior Category Breakdown

> 14-category classification from Ransack loop classifier, spec-grounded via the loop-pattern and cipher-constant catalogs.

| Category | Clusters | Iter weight | Meaning |
|---|---:|---:|---|
| `fallback` | 13 | 101 | Fallback / unclassified loops (no rule fired — likely benign Windows runtime utility) |
| `control_flow` | 3 | 61 | Control flow dispatch (indirect call, virtual table, jump table) |
| `file_io` | 5 | 11 | Filesystem read/write pair (encrypted file output) |

## 6. Execution-Order Timeline (top 10 scored loops)

> Per-loop scoring weights iteration count, crypto-call density, and classifier confidence.

| rank | score | label | iters | header IP | cluster id | module |
|---:|---:|---|---:|---|---|---|
| 1 | 22 | `unknown.utility` | 22 | `0x403f35` | `a76e1cce36c3` | `makop.exe` |
| 2 | 21 | `unknown.utility` | 21 | `0x402370` | `7a80f019490a` | `makop.exe` |
| 3 | 6 | `fs.read_write_pair` | 3 | `0x404e00` | `366585cc5203` | `makop.exe` |
| 4 | 5 | `unknown.utility` | 5 | `0x402050` | `525874fbb885` | `makop.exe` |
| 5 | 4 | `anti.short_loop` | 3 | `0x402170` | `af102ccddca5` | `makop.exe` |
| 6 | 4 | `anti.short_loop` | 3 | `0x4040c3` | `16e104041d4f` | `makop.exe` |
| 7 | 4 | `anti.short_loop` | 3 | `0x4040d0` | `af102ccddca5` | `makop.exe` |
| 8 | 4 | `anti.short_loop` | 3 | `0x4036d2` | `16e104041d4f` | `makop.exe` |
| 9 | 4 | `unknown.utility` | 4 | `0x403ff3` | `ff04f1172f0d` | `makop.exe` |
| 10 | 4 | `anti.short_loop` | 3 | `0x403492` | `94557213cbad` | `makop.exe` |
