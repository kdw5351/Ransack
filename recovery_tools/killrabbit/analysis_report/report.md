# RANSACK Evidence: `killrabbit` / `trace_KillRabbit_recovery_live`

## 1. Identity

| key | value |
|---|---|
| family | `killrabbit` |
| session_id | `trace_KillRabbit_recovery_live` |
| execution_quality | `encrypted_complete` |
| runtime_sec | `1.85` _(estimated from trace file timestamps)_ |
| crypto_executed | `True` |
| coverage notes | `(none)` |

## 2. Per-Sample Verdict

| metric | result |
|---|---|
| Key Detection | yes |
| File Recoverability | yes |
| Loop-Based Behavior Recovery | yes |

## 3. Recovery Assessment

- **Tier**: `RC_MATCHED` (3/7 strict cases passed)
- **`NO_PAYLOAD_RUN`** flag: `False` _(sample never executed an encryption pass — re-run rather than read a vacuous decision)_
- **`VALIDATED`** flag: `False` _(set only after an offline byte-level round-trip recovers ≥50% of captured ciphertexts; never set by this pipeline)_

**Evidence-axis breakdown.** Each row is a primitive an RC case keys on; the values show what the RC conjunction evaluated.

| evidence primitive | observation | which RC keys on it |
|---|---|---|
| `asym_priv_capture` | asym_blobs=0; export_apis=0 | RC-01, RC-02 |
| `memory_residue` | class=HIGH, matches=0, snapshots=366 | RC-02, RC-03, RC-06 |
| `sym_keys_inline` | unique=1 | RC-04, RC-07 |
| `hardcoded_keys` | hardcoded_key_ratio=1.00 | RC-04 |
| `weak_rng` | rng_calls=44; chain_depth=131 | RC-05 |
| `key_infra_no_sink` | sinks=247, embedded_roots=318 | RC-07 |

## 4. Behaviour Signature (hooked API counts)

| API | count |
|---|---:|
| `SystemFunction036` | 44 |
| `BCryptEncrypt` | 126 |
| `CryptEncrypt` | 378 |
| `NtWriteFile` | 161 |
| `WriteFile` | 322 |
| `NtReadFile` | 615 |
| `ReadFile` | 1230 |
| `DeleteFileW` | 88 |
| `CreateFileW` | 379 |

## 5. File Operations

| metric | value |
|---|---|
| writes | 483 |
| reads | 1845 |
| renames | 0 |
| deletes | 88 |

## 6. Loop Pipeline

| metric | value |
|---|---|
| total hot loops | 502 |
| crypto-labelled loops (among top-10 scored) | 1 |
| loop clusters (distinct labels) | 9 |
| corroborated verdicts | 35 |
| byte-gated verdicts | 0 |
| pattern-only verdicts | 11 |
| downgraded verdicts | 0 |

### 6.1 Cluster compaction by behaviour label

| behaviour label | clusters | iter weight | category |
|---|---:|---:|---|
| `unknown.utility` | 118 | 109079 | fallback |
| `fs.read_write_pair` | 186 | 10460 | file_io |
| `counter.cmp_jb_walk` | 25 | 2875 | control_flow |
| `crypto.bignum_modexp` | 9 | 1904 | crypto |
| `crypto.xor_stream` | 27 | 884 | crypto |
| `control.indirect_call` | 10 | 181 | control_flow |
| `memory.byte_or_scan` | 1 | 128 | memory_scan |
| `anti.short_loop` | 19 | 60 | control_flow |
| `crypto.aes_mixcolumns` | 2 | 4 | crypto |

### 6.2 Top 10 scored loops

| score | label | iters | header IP | cluster id |
|---:|---|---:|---|---|
| 85661 | `unknown.utility` | 85661 | `0xdf5d37` | `208d13e34ce0` |
| 9448 | `unknown.utility` | 9448 | `0xdfe4e5` | `e09741e34031` |
| 3129 | `unknown.utility` | 3129 | `0xdfa384` | `b60c522e1c15` |
| 2068 | `counter.cmp_jb_walk` | 1034 | `0xdfa2c1` | `0d711b77a120` |
| 1972 | `crypto.bignum_modexp` | 519 | `0xdfa320` | `14371a2bd88c` |
| 1904 | `fs.read_write_pair` | 907 | `0xdfa400` | `b73a14cfe5d3` |
| 1881 | `unknown.utility` | 1881 | `0xdfec53` | `0af419e52a6a` |
| 1812 | `fs.read_write_pair` | 863 | `0xdfe390` | `ba855ab725c9` |
| 1808 | `fs.read_write_pair` | 861 | `0xdfe38d` | `d46a8ec26a97` |
| 1562 | `counter.cmp_jb_walk` | 781 | `0xdfa2c1` | `0d711b77a120` |

## 7. Memory Residue

| metric | value |
|---|---|
| RSA blobs captured | 0 |
| Sym keys captured (unique hex) | 1 |
| RNG sources | 44 |
| sinks (chain) | 247 |
| residue class | HIGH |
| residue matches | 0 |
| snapshots scanned | 366 |

## 8. Detection Gaps

Each row records a limitation that explains why evidence may be missing for this sample.

| code | triggered | note |
|---|:---:|---|
| `EXEC_QUALITY_NO_PAYLOAD` | — | Increase the execution-time budget; confirm the tracer attached to the correct process; check for anti-debug bailout. |
| `ANTI_ANALYSIS_LOOPS_DETECTED` | — | Run with anti-instrumentation countermeasures; intercept anti-debug probes (IsDebuggerPresent, NtQueryInformationProcess) and return benign values. |
| `SAMPLE_IMG_NOT_INSTRUMENTED` | — | Add Windows late-load image hooks (NtMapViewOfSection, LdrLoadDll) so image-mapping patterns get instrumented. |
| `KEY_CHAIN_DEPTH_ZERO_WITH_SIGNALS` | — | A memory-copy/key-duplication primitive (memcpy, RtlMoveMemory, BCryptDuplicateKey) was not followed in the key-derivation chain, which can over-credit RC-04. |
| `PYD_NOT_REGISTERED` | — | PyCryptodome's compiled crypto extensions (.pyd) were not registered as crypto sinks, so the module surfaced no key sink. |
| `RESIDUE_DRY_WITH_RNG` | — | RNG fired but no residue snapshot matched — the key was likely zeroed mid-encryption. |
| *(no gap codes triggered)* | — | — |

## 9. Strict Recovery Cases (RC-01..RC-07)

- **Passed**: 3 / 7
- **Recoverable (strict)**: Yes

| case | name | passed | confidence | strategy | key literature |
|---|---|:---:|---:|---|---|
| `RC-01` | rsa_private_blob_exported_full | — | 0.98 | `asym_priv_universal` | Suiche, M. — wanakiwi technical writeup (2017); Trellix — Avaddon (2021) |
| `RC-02` | per_run_rsa_keypair_in_heap | — | 0.85 | `memory_residue_scan` | Bajpai & Enbody — Dissecting .NET Ransom (2018); Kolodenker et al. — PayBreak (2017) |
| `RC-03` | memory_residue_prime_scan_cryptoapi | — | 0.55 | `memory_residue_scan` | Suiche, M. — WannaCry: Decrypting files (2017); Guinet, A. — wannakey (2017) |
| `RC-04` | untraced_symmetric_key_root | ✓ | 0.95 | `untraced_root_replay` | Bajpai & Enbody — Empirical Study of Key (2020); Securelist — CryptoLocker (2014) |
| `RC-05` | weak_predictable_rng_seed | — | 0.7 | `rng_seed_replay` | AVAST Decoded — Bart ransomware decryptor (2016); Hasherezade — Petya v1 Salsa20 (2016) |
| `RC-06` | decisive_cipher_artifact_captured | ✓ | 0.65 | `concrete_artifact_to_cipher_id` | Wheeler & Needham — TEA (1994); Halderman et al. — Lest We Remember (2008) |
| `RC-07` | captured_symmetric_session_keys | ✓ | 0.95 | `sym_brute_correlation` | Kolodenker et al. — PayBreak (2017); Continella et al. — ShieldFS (2016) |

### 9.1 Recovery values for passed RCs

For each RC that fired, the block below lists the concrete value an operator would feed into the matching decryption strategy. Values are extracted from the captured cryptographic-state and memory-residue records.

#### `RC-04` — `untraced_root_replay`
- **Key bytes**: `229591d73f4a0a08471aa35f165a53e8485bc4ff5ae1a0557f2d4f621004ee62`
- **Algorithm**: AES-256, 32 B
- **Source**: `in_buf_length_only+snapshot_extracted`
- **Provenance**: `crypto_10.bin` offset 0 @ buf 0x14476c0
- **Total sym_keys**: 1

#### `RC-06` — `concrete_artifact_to_cipher_id`
- **Decisive artifacts**: 1 decisive cipher artifact: avaddon_session byte-signature (70 hits)
- **Residue class**: `HIGH`
- **Residue matches**: 0
- **Recovery basis**: A captured cipher constant / key-residue signature / family marker pins the cipher/family -- a partial-recovery path (feasibility), not a guaranteed full-key dump

#### `RC-07` — `sym_brute_correlation`
- **Total sym_keys**: 1
- **Keys with captured bytes**: 1
- **Captured key samples**: 
  - `229591d73f4a0a08471aa35f165a53e8485bc4ff5ae1a0557f2d4f621004ee62`
- **decryption_essentials.json**: present


### 9.2 Matched evidence per passed RC

Per-primitive observations that satisfied each RC conjunction.

**`RC-04` — untraced_symmetric_key_root**
- `hardcoded_key_ratio_at_least` → 247/247=1.00; threshold=0.80
- `hardcoded_key_recoverable` → direct captured key: 1 unique sym keys; threshold 1
- `has_any_event` → hit: BCryptEncrypt, CryptEncrypt

**`RC-06` — decisive_cipher_artifact_captured**
- `decisive_cipher_artifact` → 1 decisive cipher artifact: avaddon_session byte-signature (70 hits)

**`RC-07` — captured_symmetric_session_keys**
- `captured_symmetric_keys_at_least` → 1 captured sym keys (sym_keys); threshold 1
- `has_any_event` → hit: BCryptEncrypt, CryptEncrypt
- `file_present` → decryption_essentials.json: present via crypto_events_N.jsonl (kinds=kdf,keygen)


### 9.3 Behavioral evidence (process / network / anti-debug)

Complements §5 (File Operations) with categories that the file-op counters do not cover. Visible regardless of RC fire.

| category | total calls | unique APIs | top APIs (count) |
|---|---:|---:|---|
| Process injection | 0 | 0 | (none observed) |
| C2 network | 0 | 0 | (none observed) |
| Anti-debug / VM detect | 0 | 0 | (none observed) |

> **`NtSetInformationFile`** called `862` times — §5 `renames` only counts `MoveFileW` + `MoveFileExW`. When invoked with `FileInformationClass = FileRenameInformation`, this is a rename. PinTool does not currently dereference the argument; treat as upper bound on additional raw-API renames.

> **PinTool capture gap**: the categories `C2_Network`, `AntiAnalysis` are not currently hooked by the PinTool instrumentation — `0 observed` here means the API was never called *or* was called but not captured.

### 9.4 Anti-analysis evasion risk

**Status: not evasion-suspected.** The sample ran to completion with encryption activity in this trace (via hot loops and/or CryptoAPI).

- CryptoAPI encryption calls: `693` (0 = custom in-code cipher)
- File writes: `483`

## 10. Decryption Tool Synthesis Evidence

Pipeline signals that inform decryptor synthesis: the detected cipher, its round count, and the I/O chunk size.

### 10.1 Cipher detection (from crypto-labelled loops)

- **Status**: `detected`
- **Primary cipher**: `AES-256-CBC` (confidence 0.9)

### 10.2 Round count observation

- **Status**: `detected` (1 crypto-labeled loops in top 10)

| cluster | label | observed iters | header IP |
|---|---|---:|---|
| `14371a2bd88c` | `crypto.bignum_modexp` | 519 | `0xdfa320` |

### 10.3 I/O chunk size analysis

- **Status**: `detected`
- writes_total: 483, deletes_total: 88
