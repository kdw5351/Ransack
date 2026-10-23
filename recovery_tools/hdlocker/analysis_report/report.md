# RANSACK Evidence: `hdlocker` / `trace_HDLocker_recovery_live`

## 1. Identity

| key | value |
|---|---|
| family | `hdlocker` |
| session_id | `trace_HDLocker_recovery_live` |
| execution_quality | `encrypted_partial` |
| runtime_sec | `396` _(estimated from trace file timestamps)_ |
| crypto_executed | `True` |
| coverage notes | `(none)` |

## 2. Per-Sample Verdict

| metric | result |
|---|---|
| Key Detection | no |
| File Recoverability | yes |
| Loop-Based Behavior Recovery | yes |

## 3. Recovery Assessment

- **Tier**: `RC_MATCHED` (1/7 strict cases passed)
- **`NO_PAYLOAD_RUN`** flag: `False` _(sample never executed an encryption pass — re-run rather than read a vacuous decision)_
- **`VALIDATED`** flag: `False` _(set only after an offline byte-level round-trip recovers ≥50% of captured ciphertexts; never set by this pipeline)_

**Evidence-axis breakdown.** Each row is a primitive an RC case keys on; the values show what the RC conjunction evaluated.

| evidence primitive | observation | which RC keys on it |
|---|---|---|
| `asym_priv_capture` | asym_blobs=0; export_apis=0 | RC-01, RC-02 |
| `memory_residue` | class=NONE, matches=0, snapshots=0 | RC-02, RC-03, RC-06 |
| `sym_keys_inline` | unique=0 | RC-04, RC-07 |
| `hardcoded_keys` | hardcoded_key_ratio=0.00 | RC-04 |
| `weak_rng` | rng_calls=0; chain_depth=0 | RC-05 |
| `key_infra_no_sink` | sinks=0, embedded_roots=0 | RC-07 |

## 4. Behaviour Signature (hooked API counts)

| API | count |
|---|---:|
| `NtWriteFile` | 31057 |
| `WriteFile` | 62115 |
| `NtReadFile` | 13562 |
| `ReadFile` | 26546 |
| `CreateFileW` | 20609 |

## 5. File Operations

| metric | value |
|---|---|
| writes | 93172 |
| reads | 40108 |
| renames | 9891 |
| deletes | 0 |

## 6. Loop Pipeline

| metric | value |
|---|---|
| total hot loops | 324 |
| crypto-labelled loops (among top-10 scored) | 10 |
| loop clusters (distinct labels) | 11 |
| corroborated verdicts | 0 |
| byte-gated verdicts | 0 |
| pattern-only verdicts | 310 |
| downgraded verdicts | 0 |

### 6.1 Cluster compaction by behaviour label

| behaviour label | clusters | iter weight | category |
|---|---:|---:|---|
| `crypto.aes_mixcolumns` | 173 | 459 | crypto |
| `crypto.sha2_round` | 51 | 139 | crypto |
| `crypto.xor_rotate` | 27 | 83 | crypto |
| `crypto.aes_software_sbox` | 26 | 82 | crypto |
| `unknown.utility` | 6 | 20 | fallback |
| `crypto.xor_stream` | 6 | 16 | crypto |
| `anti.short_loop` | 4 | 11 | control_flow |
| `counter.cmp_jb_walk` | 2 | 5 | control_flow |
| `fs.read_write_pair` | 2 | 4 | file_io |
| `crypto.tea_round` | 1 | 3 | crypto |
| `crypto.bignum_montgomery` | 1 | 2 | crypto |

### 6.2 Top 10 scored loops

| score | label | iters | header IP | cluster id |
|---:|---|---:|---|---|
| 38 | `crypto.aes_software_sbox` | 8 | `0x118523` | `df5d1eb9c8f7` |
| 33 | `crypto.aes_mixcolumns` | 7 | `0x121b55` | `4173e59670ea` |
| 31 | `crypto.sha2_round` | 6 | `0xeb34d` | `85adc3b308af` |
| 26 | `crypto.sha2_round` | 5 | `0x1540e9` | `ca1839a977f1` |
| 24 | `crypto.aes_mixcolumns` | 5 | `0x163e33` | `a2099ee0ca9e` |
| 24 | `crypto.aes_mixcolumns` | 5 | `0xd7039` | `566fca2aa27a` |
| 20 | `crypto.sha2_round` | 4 | `0x15e335` | `e74ef85c9f62` |
| 20 | `crypto.sha2_round` | 4 | `0x1215c2` | `b5b5318afe0c` |
| 19 | `crypto.aes_mixcolumns` | 4 | `0xea661` | `827ba88232c2` |
| 19 | `crypto.aes_mixcolumns` | 4 | `0x1462ff` | `df0ac40f8396` |

## 7. Memory Residue

| metric | value |
|---|---|
| RSA blobs captured | 0 |
| Sym keys captured (unique hex) | 0 |
| RNG sources | 0 |
| sinks (chain) | 0 |
| residue class | NONE |
| residue matches | 0 |
| snapshots scanned | 0 |

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

- **Passed**: 1 / 7
- **Recoverable (strict)**: Yes

| case | name | passed | confidence | strategy | key literature |
|---|---|:---:|---:|---|---|
| `RC-01` | rsa_private_blob_exported_full | — | 0.98 | `asym_priv_universal` | Suiche, M. — wanakiwi technical writeup (2017); Trellix — Avaddon (2021) |
| `RC-02` | per_run_rsa_keypair_in_heap | — | 0.85 | `memory_residue_scan` | Bajpai & Enbody — Dissecting .NET Ransom (2018); Kolodenker et al. — PayBreak (2017) |
| `RC-03` | memory_residue_prime_scan_cryptoapi | — | 0.55 | `memory_residue_scan` | Suiche, M. — WannaCry: Decrypting files (2017); Guinet, A. — wannakey (2017) |
| `RC-04` | untraced_symmetric_key_root | — | 0.95 | `untraced_root_replay` | Bajpai & Enbody — Empirical Study of Key (2020); Securelist — CryptoLocker (2014) |
| `RC-05` | weak_predictable_rng_seed | — | 0.7 | `rng_seed_replay` | AVAST Decoded — Bart ransomware decryptor (2016); Hasherezade — Petya v1 Salsa20 (2016) |
| `RC-06` | decisive_cipher_artifact_captured | ✓ | 0.65 | `concrete_artifact_to_cipher_id` | Wheeler & Needham — TEA (1994); Halderman et al. — Lest We Remember (2008) |
| `RC-07` | captured_symmetric_session_keys | — | 0.95 | `sym_brute_correlation` | Kolodenker et al. — PayBreak (2017); Continella et al. — ShieldFS (2016) |

### 9.1 Recovery values for passed RCs

For each RC that fired, the block below lists the concrete value an operator would feed into the matching decryption strategy. Values are extracted from the captured cryptographic-state and memory-residue records.

#### `RC-06` — `concrete_artifact_to_cipher_id`
- **Decisive artifacts**: 1 decisive cipher artifact, ambiguous (needs disambiguation): tea_delta constant (TEA) at loop 129
- **Residue class**: `NONE`
- **Residue matches**: 0
- **Recovery basis**: A captured cipher constant / key-residue signature / family marker pins the cipher/family -- a partial-recovery path (feasibility), not a guaranteed full-key dump


### 9.2 Matched evidence per passed RC

Per-primitive observations that satisfied each RC conjunction.

**`RC-06` — decisive_cipher_artifact_captured**
- `decisive_cipher_artifact` → 1 decisive cipher artifact, ambiguous (needs disambiguation): tea_delta constant (TEA) at loop 129


### 9.3 Behavioral evidence (process / network / anti-debug)

Complements §5 (File Operations) with categories that the file-op counters do not cover. Visible regardless of RC fire.

| category | total calls | unique APIs | top APIs (count) |
|---|---:|---:|---|
| Process injection | 0 | 0 | (none observed) |
| C2 network | 0 | 0 | (none observed) |
| Anti-debug / VM detect | 0 | 0 | (none observed) |

> **`NtSetInformationFile`** called `84325` times — §5 `renames` only counts `MoveFileW` + `MoveFileExW`. When invoked with `FileInformationClass = FileRenameInformation`, this is a rename. PinTool does not currently dereference the argument; treat as upper bound on additional raw-API renames.

> **PinTool capture gap**: the categories `C2_Network`, `AntiAnalysis` are not currently hooked by the PinTool instrumentation — `0 observed` here means the API was never called *or* was called but not captured.

### 9.4 Anti-analysis evasion risk

**Status: not evasion-suspected.** The sample ran to completion with encryption activity in this trace (via hot loops and/or CryptoAPI).

- CryptoAPI encryption calls: `0` (0 = custom in-code cipher)
- File writes: `93172`

## 10. Decryption Tool Synthesis Evidence

Pipeline signals that inform decryptor synthesis: the detected cipher, its round count, and the I/O chunk size.

### 10.1 Cipher detection (from crypto-labelled loops)

- **Status**: `detected`
- **Primary cipher**: `TEA (16-round; decisive constant tea_delta)` (confidence 0.9)

### 10.2 Round count observation

- **Status**: `detected` (10 crypto-labeled loops in top 10)

| cluster | label | observed iters | header IP |
|---|---|---:|---|
| `df5d1eb9c8f7` | `crypto.aes_software_sbox` | 8 | `0x118523` |
| `4173e59670ea` | `crypto.aes_mixcolumns` | 7 | `0x121b55` |
| `85adc3b308af` | `crypto.sha2_round` | 6 | `0xeb34d` |
| `ca1839a977f1` | `crypto.sha2_round` | 5 | `0x1540e9` |
| `a2099ee0ca9e` | `crypto.aes_mixcolumns` | 5 | `0x163e33` |
| `566fca2aa27a` | `crypto.aes_mixcolumns` | 5 | `0xd7039` |
| `e74ef85c9f62` | `crypto.sha2_round` | 4 | `0x15e335` |
| `b5b5318afe0c` | `crypto.sha2_round` | 4 | `0x1215c2` |
| `827ba88232c2` | `crypto.aes_mixcolumns` | 4 | `0xea661` |
| `df0ac40f8396` | `crypto.aes_mixcolumns` | 4 | `0x1462ff` |

### 10.3 I/O chunk size analysis

- **Status**: `detected`
- writes_total: 93172, deletes_total: 0
