# Sample Report — `trace_GarrantyCrypt_recovery_live`

> Unified per-sample evidence report with an execution-order timeline and per-loop behavior categorization.

## 1. Identity

| field | value |
|---|---|
| family tag | `garrantycrypt` |
| session | `trace_GarrantyCrypt_recovery_live` |
| execution_quality | **encrypted_complete** |
| recovery tier | **RC_MATCHED** (4/7 RC cases matched) |
| `NO_PAYLOAD_RUN` flag | `False` |
| `VALIDATED` flag | `False` |
| primary cipher | **XOR (stream) (heuristic, unconfirmed)** |
| key_chain_depth | 5 |
| runtime_sec | 0.27 |

## 2. Recovery Verdict

- **strict RC checklist (RC-01..RC-07)**: `RC-01`, `RC-02`, `RC-03`, `RC-06`
- **Loop-Based Crypto Behavior Identification**: yes (primary cipher = `XOR (stream) (heuristic, unconfirmed)`)
- **Key Detection** (any of: captured asymmetric private key, memory-residue key, inline symmetric key, hardcoded key, or RNG output): yes
- **File Recoverability**: yes

## 3. Cryptographic Behavior (API trace)

| metric | count | spec/source |
|---|---:|---|
| RNG calls | 15925 | FIPS-140-2 §4.6 (NIST SP 800-90A); MS Learn CNG/CryptoAPI |
| Sym encrypt calls | 31858 | MS Learn BCryptEncrypt; FIPS-197 (AES) |
| Asym blobs captured | 0 | MS Learn BCryptExportKey; PKCS#1 |
| Unique sym keys (chain) | 0 | RFC 5246 / FIPS-197 |
| KDF chain depth | 5 | RFC 2104 (HMAC) / RFC 5869 (HKDF) |
| Hardcoded-key ratio | 0.00 | RC-04 indicator (Bajpai & Enbody 2020) |

## 4. File Operations

| op | count |
|---|---:|
| writes | 12661 |
| reads | 5901 |
| renames | 920 |
| deletes | 0 |

## 5. Loop Behavior Category Breakdown

> 14-category classification from Ransack loop classifier, spec-grounded via the loop-pattern and cipher-constant catalogs.

| Category | Clusters | Iter weight | Meaning |
|---|---:|---:|---|
| `fallback` | 5 | 12 | Fallback / unclassified loops (no rule fired — likely benign Windows runtime utility) |
| `control_flow` | 4 | 12 | Control flow dispatch (indirect call, virtual table, jump table) |
| `crypto` | 2 | 6 | Crypto-labelled loops (AES round/sbox, ChaCha quarter, XOR stream/chain, TEA round, hash compress) |
| `file_io` | 1 | 2 | Filesystem read/write pair (encrypted file output) |

## 6. Execution-Order Timeline (top 10 scored loops)

> Per-loop scoring weights iteration count, crypto-call density, and classifier confidence.

| rank | score | label | iters | header IP | cluster id | module |
|---:|---:|---|---:|---|---|---|
| 1 | 15 | `crypto.sha2_round` | 3 | `0x652b2d` | `cf97058c5c90` | `garrantycrypt.exe` |
| 2 | 11 | `crypto.xor_stream` | 3 | `0x652f6f` | `f682888231fd` | `garrantycrypt.exe` |
| 3 | 4 | `fs.read_write_pair` | 2 | `0x6535ed` | `d671b4edac2b` | `garrantycrypt.exe` |
| 4 | 4 | `anti.short_loop` | 3 | `0x653433` | `5b6b9b67942c` | `garrantycrypt.exe` |
| 5 | 4 | `anti.short_loop` | 3 | `0x653469` | `bdc97bf61315` | `garrantycrypt.exe` |
| 6 | 4 | `anti.short_loop` | 3 | `0x6534cb` | `43a3f2bf6db1` | `garrantycrypt.exe` |
| 7 | 4 | `anti.short_loop` | 3 | `0x652abe` | `7c41a6363515` | `garrantycrypt.exe` |
| 8 | 3 | `unknown.utility` | 3 | `0x652d25` | `8fede32218f7` | `garrantycrypt.exe` |
| 9 | 3 | `unknown.utility` | 3 | `0x652f33` | `2714c93b1f77` | `garrantycrypt.exe` |
| 10 | 2 | `unknown.utility` | 2 | `0x653903` | `52ac198e1d44` | `garrantycrypt.exe` |
