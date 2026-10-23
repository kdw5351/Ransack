# RANSACK Evidence: `akira` / `trace_Akira_recovery_live`

## 1. Identity

| key | value |
|---|---|
| family | `akira` |
| session_id | `trace_Akira_recovery_live` |
| execution_quality | `encrypted_complete` |
| runtime_sec | `59.53` _(estimated from trace file timestamps)_ |
| crypto_executed | `True` |
| coverage notes | `(none)` |

## 2. Per-Sample Verdict

| metric | result |
|---|---|
| Key Detection | yes |
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
| `memory_residue` | class=NONE, matches=0, snapshots=67 | RC-02, RC-03, RC-06 |
| `sym_keys_inline` | unique=0 | RC-04, RC-07 |
| `hardcoded_keys` | hardcoded_key_ratio=1.00 | RC-04 |
| `weak_rng` | rng_calls=7; chain_depth=23 | RC-05 |
| `key_infra_no_sink` | sinks=4, embedded_roots=34 | RC-07 |

## 4. Behaviour Signature (hooked API counts)

| API | count |
|---|---:|
| `SystemFunction036` | 3 |
| `CryptGenRandom` | 4 |
| `BCryptEncrypt` | 2 |
| `CryptEncrypt` | 4 |
| `NtWriteFile` | 16685 |
| `WriteFile` | 33372 |
| `NtReadFile` | 9732 |
| `ReadFile` | 19464 |
| `CreateFileW` | 39496 |

## 5. File Operations

| metric | value |
|---|---|
| writes | 50057 |
| reads | 29196 |
| renames | 11150 |
| deletes | 0 |

## 6. Loop Pipeline

| metric | value |
|---|---|
| total hot loops | 147 |
| crypto-labelled loops (among top-10 scored) | 6 |
| loop clusters (distinct labels) | 8 |
| corroborated verdicts | 9 |
| byte-gated verdicts | 0 |
| pattern-only verdicts | 0 |
| downgraded verdicts | 0 |

### 6.1 Cluster compaction by behaviour label

| behaviour label | clusters | iter weight | category |
|---|---:|---:|---|
| `unknown.utility` | 45 | 209 | fallback |
| `fs.read_write_pair` | 24 | 75 | file_io |
| `anti.short_loop` | 2 | 27 | control_flow |
| `memory.bulk_movups_sse` | 5 | 18 | memory_copy |
| `crypto.xor_rotate` | 2 | 12 | crypto |
| `counter.cmp_jb_walk` | 2 | 6 | control_flow |
| `crypto.xor_stream` | 3 | 6 | crypto |
| `crypto.aes_mixcolumns` | 2 | 4 | crypto |

### 6.2 Top 10 scored loops

| score | label | iters | header IP | cluster id |
|---:|---|---:|---|---|
| 12 | `crypto.xor_rotate` | 3 | `0x7ff7a5db93b0` | `869ea272937f` |
| 12 | `crypto.xor_rotate` | 3 | `0x7ff7a5db92f0` | `a6efe18c32b4` |
| 12 | `crypto.xor_rotate` | 3 | `0x7ff7a5db93b0` | `869ea272937f` |
| 12 | `crypto.xor_rotate` | 3 | `0x7ff7a5db92f0` | `a6efe18c32b4` |
| 9 | `crypto.aes_mixcolumns` | 2 | `0x7ff7a5dcb940` | `ddd9540e22e5` |
| 9 | `crypto.aes_mixcolumns` | 2 | `0x7ff7a5dcb7c0` | `1f12634adf41` |
| 8 | `memory.bulk_movups_sse` | 3 | `0x7ff7a5dffda0` | `378f05e33525` |
| 8 | `fs.read_write_pair` | 4 | `0x7ff7a5de8a31` | `2e936ff9c17d` |
| 8 | `fs.read_write_pair` | 4 | `0x7ff7a5dc9c70` | `afdd9d2dc2f8` |
| 8 | `memory.bulk_movups_sse` | 3 | `0x7ff7a5dffda0` | `378f05e33525` |

## 7. Memory Residue

| metric | value |
|---|---|
| RSA blobs captured | 0 |
| Sym keys captured (unique hex) | 0 |
| RNG sources | 7 |
| sinks (chain) | 4 |
| residue class | NONE |
| residue matches | 0 |
| snapshots scanned | 67 |

## 8. Detection Gaps

Each row records a limitation that explains why evidence may be missing for this sample.

| code | triggered | note |
|---|:---:|---|
| `EXEC_QUALITY_NO_PAYLOAD` | — | Increase the execution-time budget; confirm the tracer attached to the correct process; check for anti-debug bailout. |
| `ANTI_ANALYSIS_LOOPS_DETECTED` | — | Run with anti-instrumentation countermeasures; intercept anti-debug probes (IsDebuggerPresent, NtQueryInformationProcess) and return benign values. |
| `SAMPLE_IMG_NOT_INSTRUMENTED` | — | Add Windows late-load image hooks (NtMapViewOfSection, LdrLoadDll) so image-mapping patterns get instrumented. |
| `KEY_CHAIN_DEPTH_ZERO_WITH_SIGNALS` | — | A memory-copy/key-duplication primitive (memcpy, RtlMoveMemory, BCryptDuplicateKey) was not followed in the key-derivation chain, which can over-credit RC-04. |
| `PYD_NOT_REGISTERED` | — | PyCryptodome's compiled crypto extensions (.pyd) were not registered as crypto sinks, so the module surfaced no key sink. |
| `RESIDUE_DRY_WITH_RNG` | ✓ | RNG fired but no residue snapshot matched — the key was likely zeroed mid-encryption. |

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
| `RC-06` | decisive_cipher_artifact_captured | — | 0.65 | `concrete_artifact_to_cipher_id` | Wheeler & Needham — TEA (1994); Halderman et al. — Lest We Remember (2008) |
| `RC-07` | captured_symmetric_session_keys | ✓ | 0.95 | `sym_brute_correlation` | Kolodenker et al. — PayBreak (2017); Continella et al. — ShieldFS (2016) |

### 9.1 Recovery values for passed RCs

For each RC that fired, the block below lists the concrete value an operator would feed into the matching decryption strategy. Values are extracted from the captured cryptographic-state and memory-residue records.

#### `RC-07` — `sym_brute_correlation`
- **Source**: captured plaintext at the RSA-wrap input (PayBreak class)
- **Total wrapped session keys**: 1
- **Keys with captured bytes**: 1
- **Captured key samples**: 
  - `9c6e2dbacb621997ebac79a2a947354d0e00d76b63b0039d80a083de2bde0bea`
- **Trailing bytes (IV / nonce)**: `81a1c388de064073`
- **decryption_essentials.json**: present


### 9.2 Matched evidence per passed RC

Per-primitive observations that satisfied each RC conjunction.

**`RC-07` — captured_symmetric_session_keys**
- `captured_symmetric_keys_at_least` → 1 captured sym keys (wrapped-key sink_plaintext); threshold 1
- `has_any_event` → hit: BCryptEncrypt, CryptEncrypt
- `file_present` → decryption_essentials.json: present via crypto_events_N.jsonl (kinds=key_import)


### 9.3 Behavioral evidence (process / network / anti-debug)

Complements §5 (File Operations) with categories that the file-op counters do not cover. Visible regardless of RC fire.

| category | total calls | unique APIs | top APIs (count) |
|---|---:|---:|---|
| Process injection | 0 | 0 | (none observed) |
| C2 network | 0 | 0 | (none observed) |
| Anti-debug / VM detect | 0 | 0 | (none observed) |

> **`NtSetInformationFile`** called `12059` times — §5 `renames` only counts `MoveFileW` + `MoveFileExW`. When invoked with `FileInformationClass = FileRenameInformation`, this is a rename. PinTool does not currently dereference the argument; treat as upper bound on additional raw-API renames.

> **PinTool capture gap**: the categories `C2_Network`, `AntiAnalysis` are not currently hooked by the PinTool instrumentation — `0 observed` here means the API was never called *or* was called but not captured.

### 9.4 Anti-analysis evasion risk

**Status: not evasion-suspected.** The sample ran to completion with encryption activity in this trace (via hot loops and/or CryptoAPI).

- CryptoAPI encryption calls: `8` (0 = custom in-code cipher)
- File writes: `50057`

## 10. Decryption Tool Synthesis Evidence

Pipeline signals that inform decryptor synthesis: the detected cipher, its round count, and the I/O chunk size.

### 10.1 Cipher detection (from crypto-labelled loops)

- **Status**: `detected`
- **Primary cipher**: `XOR (rotate) (heuristic, unconfirmed)` (confidence 0.35)

### 10.2 Round count observation

- **Status**: `detected` (6 crypto-labeled loops in top 10)

| cluster | label | observed iters | header IP |
|---|---|---:|---|
| `869ea272937f` | `crypto.xor_rotate` | 3 | `0x7ff7a5db93b0` |
| `a6efe18c32b4` | `crypto.xor_rotate` | 3 | `0x7ff7a5db92f0` |
| `869ea272937f` | `crypto.xor_rotate` | 3 | `0x7ff7a5db93b0` |
| `a6efe18c32b4` | `crypto.xor_rotate` | 3 | `0x7ff7a5db92f0` |
| `ddd9540e22e5` | `crypto.aes_mixcolumns` | 2 | `0x7ff7a5dcb940` |
| `1f12634adf41` | `crypto.aes_mixcolumns` | 2 | `0x7ff7a5dcb7c0` |

### 10.3 I/O chunk size analysis

- **Status**: `detected`
- writes_total: 50057, deletes_total: 0
