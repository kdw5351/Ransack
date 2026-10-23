# RANSACK Evidence: `garrantycrypt` / `trace_GarrantyCrypt_recovery_live`

## 1. Identity

| key | value |
|---|---|
| family | `garrantycrypt` |
| session_id | `trace_GarrantyCrypt_recovery_live` |
| execution_quality | `encrypted_complete` |
| runtime_sec | `0.27` _(estimated from trace file timestamps)_ |
| crypto_executed | `True` |
| coverage notes | `(none)` |

## 2. Per-Sample Verdict

| metric | result |
|---|---|
| Key Detection | yes |
| File Recoverability | yes |
| Loop-Based Behavior Recovery | yes |

## 3. Recovery Assessment

- **Tier**: `RC_MATCHED` (4/7 strict cases passed)
- **`NO_PAYLOAD_RUN`** flag: `False` _(sample never executed an encryption pass — re-run rather than read a vacuous decision)_
- **`VALIDATED`** flag: `False` _(set only after an offline byte-level round-trip recovers ≥50% of captured ciphertexts; never set by this pipeline)_

**Evidence-axis breakdown.** Each row is a primitive an RC case keys on; the values show what the RC conjunction evaluated.

| evidence primitive | observation | which RC keys on it |
|---|---|---|
| `asym_priv_capture` | asym_blobs=0; export_apis=6 | RC-01, RC-02 |
| `memory_residue` | class=HIGH, matches=0, snapshots=275 | RC-02, RC-03, RC-06 |
| `sym_keys_inline` | unique=0 | RC-04, RC-07 |
| `hardcoded_keys` | hardcoded_key_ratio=0.00 | RC-04 |
| `weak_rng` | rng_calls=15925; chain_depth=5 | RC-05 |
| `key_infra_no_sink` | sinks=5316, embedded_roots=15 | RC-07 |

## 4. Behaviour Signature (hooked API counts)

| API | count |
|---|---:|
| `SystemFunction036` | 5309 |
| `CryptGenRandom` | 10616 |
| `BCryptEncrypt` | 10618 |
| `CryptEncrypt` | 21240 |
| `BCryptExportKey` | 2 |
| `CryptExportKey` | 4 |
| `NtWriteFile` | 4221 |
| `WriteFile` | 8440 |
| `NtReadFile` | 1970 |
| `ReadFile` | 3931 |
| `MoveFileW` | 920 |
| `CreateFileW` | 12375 |

## 5. File Operations

| metric | value |
|---|---|
| writes | 12661 |
| reads | 5901 |
| renames | 920 |
| deletes | 0 |

## 6. Loop Pipeline

| metric | value |
|---|---|
| total hot loops | 12 |
| crypto-labelled loops (among top-10 scored) | 2 |
| loop clusters (distinct labels) | 5 |
| corroborated verdicts | 1 |
| byte-gated verdicts | 0 |
| pattern-only verdicts | 1 |
| downgraded verdicts | 0 |

### 6.1 Cluster compaction by behaviour label

| behaviour label | clusters | iter weight | category |
|---|---:|---:|---|
| `unknown.utility` | 5 | 12 | fallback |
| `anti.short_loop` | 4 | 12 | control_flow |
| `crypto.xor_stream` | 1 | 3 | crypto |
| `crypto.sha2_round` | 1 | 3 | crypto |
| `fs.read_write_pair` | 1 | 2 | file_io |

### 6.2 Top 10 scored loops

| score | label | iters | header IP | cluster id |
|---:|---|---:|---|---|
| 15 | `crypto.sha2_round` | 3 | `0x652b2d` | `cf97058c5c90` |
| 11 | `crypto.xor_stream` | 3 | `0x652f6f` | `f682888231fd` |
| 4 | `fs.read_write_pair` | 2 | `0x6535ed` | `d671b4edac2b` |
| 4 | `anti.short_loop` | 3 | `0x653433` | `5b6b9b67942c` |
| 4 | `anti.short_loop` | 3 | `0x653469` | `bdc97bf61315` |
| 4 | `anti.short_loop` | 3 | `0x6534cb` | `43a3f2bf6db1` |
| 4 | `anti.short_loop` | 3 | `0x652abe` | `7c41a6363515` |
| 3 | `unknown.utility` | 3 | `0x652d25` | `8fede32218f7` |
| 3 | `unknown.utility` | 3 | `0x652f33` | `2714c93b1f77` |
| 2 | `unknown.utility` | 2 | `0x653903` | `52ac198e1d44` |

## 7. Memory Residue

| metric | value |
|---|---|
| RSA blobs captured | 0 |
| Sym keys captured (unique hex) | 0 |
| RNG sources | 15925 |
| sinks (chain) | 5316 |
| residue class | HIGH |
| residue matches | 0 |
| snapshots scanned | 275 |

## 8. Detection Gaps

Each row records a limitation that explains why evidence may be missing for this sample.

| code | triggered | note |
|---|:---:|---|
| `EXEC_QUALITY_NO_PAYLOAD` | — | Increase the execution-time budget; confirm the tracer attached to the correct process; check for anti-debug bailout. |
| `ANTI_ANALYSIS_LOOPS_DETECTED` | ✓ | Run with anti-instrumentation countermeasures; intercept anti-debug probes (IsDebuggerPresent, NtQueryInformationProcess) and return benign values. |
| `SAMPLE_IMG_NOT_INSTRUMENTED` | — | Add Windows late-load image hooks (NtMapViewOfSection, LdrLoadDll) so image-mapping patterns get instrumented. |
| `KEY_CHAIN_DEPTH_ZERO_WITH_SIGNALS` | — | A memory-copy/key-duplication primitive (memcpy, RtlMoveMemory, BCryptDuplicateKey) was not followed in the key-derivation chain, which can over-credit RC-04. |
| `PYD_NOT_REGISTERED` | — | PyCryptodome's compiled crypto extensions (.pyd) were not registered as crypto sinks, so the module surfaced no key sink. |
| `RESIDUE_DRY_WITH_RNG` | — | RNG fired but no residue snapshot matched — the key was likely zeroed mid-encryption. |

## 9. Strict Recovery Cases (RC-01..RC-07)

- **Passed**: 4 / 7
- **Recoverable (strict)**: Yes

| case | name | passed | confidence | strategy | key literature |
|---|---|:---:|---:|---|---|
| `RC-01` | rsa_private_blob_exported_full | ✓ | 0.98 | `asym_priv_universal` | Suiche, M. — wanakiwi technical writeup (2017); Trellix — Avaddon (2021) |
| `RC-02` | per_run_rsa_keypair_in_heap | ✓ | 0.85 | `memory_residue_scan` | Bajpai & Enbody — Dissecting .NET Ransom (2018); Kolodenker et al. — PayBreak (2017) |
| `RC-03` | memory_residue_prime_scan_cryptoapi | ✓ | 0.55 | `memory_residue_scan` | Suiche, M. — WannaCry: Decrypting files (2017); Guinet, A. — wannakey (2017) |
| `RC-04` | untraced_symmetric_key_root | — | 0.95 | `untraced_root_replay` | Bajpai & Enbody — Empirical Study of Key (2020); Securelist — CryptoLocker (2014) |
| `RC-05` | weak_predictable_rng_seed | — | 0.7 | `rng_seed_replay` | AVAST Decoded — Bart ransomware decryptor (2016); Hasherezade — Petya v1 Salsa20 (2016) |
| `RC-06` | decisive_cipher_artifact_captured | ✓ | 0.65 | `concrete_artifact_to_cipher_id` | Wheeler & Needham — TEA (1994); Halderman et al. — Lest We Remember (2008) |
| `RC-07` | captured_symmetric_session_keys | — | 0.95 | `sym_brute_correlation` | Kolodenker et al. — PayBreak (2017); Continella et al. — ShieldFS (2016) |

### 9.1 Recovery values for passed RCs

For each RC that fired, the block below lists the concrete value an operator would feed into the matching decryption strategy. Values are extracted from the captured cryptographic-state and memory-residue records.

#### `RC-01` — `asym_priv_universal`
- **Status**: (blob present but no detail extracted)

#### `RC-02` — `memory_residue_scan`
- **RSA keygen APIs**: `BCryptGenerateKeyPair`=1, `CryptGenKey`=2, `BCryptFinalizeKeyPair`=1
- **Residue class**: `HIGH` (threshold = HIGH)
- **Residue matches**: 0
- **Unique tags**: (none)
- **Promotion warning**: real match count = 0 but residue_class promoted `NONE` → `HIGH` via `wanakiwi_prime:162, cryptoapi_rsa_blob:1`. **This may be a false positive — `aeskeyfind` matches AES round-key schedules, not RSA keypairs (RC-02 requires an RSA keypair in memory). Audit required.**

#### `RC-03` — `memory_residue_scan`
- **CryptoAPI keygen APIs**: `CryptGenKey`=2, `CryptAcquireContextA`=2
- **Residue class**: `HIGH` (threshold = MID, RC-03 = wanakiwi 128B window)
- **Residue matches**: 0
- **Unique tags**: (none)
- **Decryption technique**: Slide 128 B window over heap, accept candidate iff N % candidate == 0 against on-disk public modulus
- **Promotion warning**: real match count = 0 but residue_class promoted `NONE` → `HIGH` via `wanakiwi_prime:162, cryptoapi_rsa_blob:1`. **Audit required: RC-03 requires an RSA-prime scan; AES-key promotion may not be valid evidence here.**

#### `RC-06` — `concrete_artifact_to_cipher_id`
- **Decisive artifacts**: 2 decisive cipher artifacts: cryptoapi_rsa_blob byte-signature (1 hit), wanakiwi_prime byte-signature (162 hits)
- **Residue class**: `HIGH`
- **Residue matches**: 0
- **Recovery basis**: A captured cipher constant / key-residue signature / family marker pins the cipher/family -- a partial-recovery path (feasibility), not a guaranteed full-key dump


### 9.2 Matched evidence per passed RC

Per-primitive observations that satisfied each RC conjunction.

**`RC-01` — rsa_private_blob_exported_full**
- `has_any_event` → hit: BCryptExportKey, BCryptFinalizeKeyPair, CryptExportKey
- `residue_class_at_least` → residue=HIGH (0 matches, 0 unique tags, 275 snapshots scanned); threshold=HIGH

**`RC-02` — per_run_rsa_keypair_in_heap**
- `residue_class_at_least` → residue=HIGH (0 matches, 0 unique tags, 275 snapshots scanned); threshold=HIGH
- `file_present` → key_residue_map.json: present via chunked key_residue_snapshots_N.jsonl

**`RC-03` — memory_residue_prime_scan_cryptoapi**
- `has_any_event` → hit: CryptAcquireContextA, CryptGenKey
- `residue_class_at_least` → residue=HIGH (0 matches, 0 unique tags, 275 snapshots scanned); threshold=MID
- `file_present` → key_residue_map.json: present via chunked key_residue_snapshots_N.jsonl

**`RC-06` — decisive_cipher_artifact_captured**
- `decisive_cipher_artifact` → 2 decisive cipher artifacts: cryptoapi_rsa_blob byte-signature (1 hit), wanakiwi_prime byte-signature (162 hits)


### 9.3 Behavioral evidence (process / network / anti-debug)

Complements §5 (File Operations) with categories that the file-op counters do not cover. Visible regardless of RC fire.

| category | total calls | unique APIs | top APIs (count) |
|---|---:|---:|---|
| Process injection | 0 | 0 | (none observed) |
| C2 network | 0 | 0 | (none observed) |
| Anti-debug / VM detect | 0 | 0 | (none observed) |

> **`NtSetInformationFile`** called `4943` times — §5 `renames` only counts `MoveFileW` + `MoveFileExW`. When invoked with `FileInformationClass = FileRenameInformation`, this is a rename. PinTool does not currently dereference the argument; treat as upper bound on additional raw-API renames.

> **PinTool capture gap**: the categories `C2_Network`, `AntiAnalysis` are not currently hooked by the PinTool instrumentation — `0 observed` here means the API was never called *or* was called but not captured.

### 9.4 Anti-analysis evasion risk

**Status: not evasion-suspected.** The sample ran to completion with encryption activity in this trace (via hot loops and/or CryptoAPI).

- CryptoAPI encryption calls: `42477` (0 = custom in-code cipher)
- File writes: `12661`

## 10. Decryption Tool Synthesis Evidence

Pipeline signals that inform decryptor synthesis: the detected cipher, its round count, and the I/O chunk size.

### 10.1 Cipher detection (from crypto-labelled loops)

- **Status**: `detected`
- **Primary cipher**: `XOR (stream) (heuristic, unconfirmed)` (confidence 0.35)

### 10.2 Round count observation

- **Status**: `detected` (2 crypto-labeled loops in top 10)

| cluster | label | observed iters | header IP |
|---|---|---:|---|
| `cf97058c5c90` | `crypto.sha2_round` | 3 | `0x652b2d` |
| `f682888231fd` | `crypto.xor_stream` | 3 | `0x652f6f` |

### 10.3 I/O chunk size analysis

- **Status**: `detected`
- writes_total: 12661, deletes_total: 0
