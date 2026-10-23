# RANSACK Evidence: `razrusheniye` / `trace_Razrusheniye_recovery_live`

## 1. Identity

| key | value |
|---|---|
| family | `razrusheniye` |
| session_id | `trace_Razrusheniye_recovery_live` |
| execution_quality | `encrypted_complete` |
| runtime_sec | `7.69` _(estimated from trace file timestamps)_ |
| crypto_executed | `True` |
| coverage notes | `(none)` |

## 2. Per-Sample Verdict

| metric | result |
|---|---|
| Key Detection | yes |
| File Recoverability | yes |
| Loop-Based Behavior Recovery | no |

## 3. Recovery Assessment

- **Tier**: `RC_MATCHED` (4/7 strict cases passed)
- **`NO_PAYLOAD_RUN`** flag: `False` _(sample never executed an encryption pass — re-run rather than read a vacuous decision)_
- **`VALIDATED`** flag: `False` _(set only after an offline byte-level round-trip recovers ≥50% of captured ciphertexts; never set by this pipeline)_

**Evidence-axis breakdown.** Each row is a primitive an RC case keys on; the values show what the RC conjunction evaluated.

| evidence primitive | observation | which RC keys on it |
|---|---|---|
| `asym_priv_capture` | asym_blobs=0; export_apis=2 | RC-01, RC-02 |
| `memory_residue` | class=HIGH, matches=0, snapshots=435 | RC-02, RC-03, RC-06 |
| `sym_keys_inline` | unique=1 | RC-04, RC-07 |
| `hardcoded_keys` | hardcoded_key_ratio=1.00 | RC-04 |
| `weak_rng` | rng_calls=21314; chain_depth=21275 | RC-05 |
| `key_infra_no_sink` | sinks=42148, embedded_roots=21419 | RC-07 |

## 4. Behaviour Signature (hooked API counts)

| API | count |
|---|---:|
| `BCryptGenRandom` | 33 |
| `SystemFunction036` | 21279 |
| `CryptGenRandom` | 2 |
| `BCryptEncrypt` | 42550 |
| `CryptEncrypt` | 127650 |
| `CryptExportKey` | 2 |
| `NtWriteFile` | 26049 |
| `WriteFile` | 47186 |
| `NtReadFile` | 28775 |
| `ReadFile` | 57551 |
| `DeleteFileW` | 21137 |
| `CreateFileW` | 6177 |

## 5. File Operations

| metric | value |
|---|---|
| writes | 73235 |
| reads | 86326 |
| renames | 0 |
| deletes | 63411 |

## 6. Loop Pipeline

| metric | value |
|---|---|
| total hot loops | 18 |
| crypto-labelled loops (among top-10 scored) | 0 |
| loop clusters (distinct labels) | 4 |
| corroborated verdicts | 0 |
| byte-gated verdicts | 0 |
| pattern-only verdicts | 0 |
| downgraded verdicts | 0 |

### 6.1 Cluster compaction by behaviour label

| behaviour label | clusters | iter weight | category |
|---|---:|---:|---|
| `unknown.utility` | 5 | 363 | fallback |
| `anti.short_loop` | 1 | 9 | control_flow |
| `fs.read_write_pair` | 2 | 7 | file_io |
| `encoding.base64_pack` | 1 | 3 | encoding |

### 6.2 Top 10 scored loops

| score | label | iters | header IP | cluster id |
|---:|---|---:|---|---|
| 269 | `unknown.utility` | 269 | `0x7ff6d0341c22` | `b8cc93a30fac` |
| 38 | `unknown.utility` | 38 | `0x7ff6d03418b0` | `14d9992ba3f7` |
| 33 | `unknown.utility` | 33 | `0x7ff6d0341b71` | `14d9992ba3f7` |
| 6 | `fs.read_write_pair` | 3 | `0x7ff6d0341a70` | `77f9e3fcea27` |
| 6 | `encoding.base64_pack` | 3 | `0x7ff6d0341f72` | `e8fd9b3ddf1d` |
| 5 | `unknown.utility` | 5 | `0x7ff6d0341bf0` | `ca3ea8cb9f92` |
| 4 | `fs.read_write_pair` | 2 | `0x7ff6d0341ad0` | `5a6fd2f87e20` |
| 4 | `anti.short_loop` | 3 | `0x7ff6d0341720` | `a99026232e05` |
| 4 | `fs.read_write_pair` | 2 | `0x7ff6d0341803` | `5a6fd2f87e20` |
| 4 | `anti.short_loop` | 3 | `0x7ff6d0341283` | `a99026232e05` |

## 7. Memory Residue

| metric | value |
|---|---|
| RSA blobs captured | 0 |
| Sym keys captured (unique hex) | 1 |
| RNG sources | 21314 |
| sinks (chain) | 42148 |
| residue class | HIGH |
| residue matches | 0 |
| snapshots scanned | 435 |

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
| `RC-01` | rsa_private_blob_exported_full | — | 0.98 | `asym_priv_universal` | Suiche, M. — wanakiwi technical writeup (2017); Trellix — Avaddon (2021) |
| `RC-02` | per_run_rsa_keypair_in_heap | — | 0.85 | `memory_residue_scan` | Bajpai & Enbody — Dissecting .NET Ransom (2018); Kolodenker et al. — PayBreak (2017) |
| `RC-03` | memory_residue_prime_scan_cryptoapi | — | 0.55 | `memory_residue_scan` | Suiche, M. — WannaCry: Decrypting files (2017); Guinet, A. — wannakey (2017) |
| `RC-04` | untraced_symmetric_key_root | ✓ | 0.95 | `untraced_root_replay` | Bajpai & Enbody — Empirical Study of Key (2020); Securelist — CryptoLocker (2014) |
| `RC-05` | weak_predictable_rng_seed | ✓ | 0.7 | `rng_seed_replay` | AVAST Decoded — Bart ransomware decryptor (2016); Hasherezade — Petya v1 Salsa20 (2016) |
| `RC-06` | decisive_cipher_artifact_captured | ✓ | 0.65 | `concrete_artifact_to_cipher_id` | Wheeler & Needham — TEA (1994); Halderman et al. — Lest We Remember (2008) |
| `RC-07` | captured_symmetric_session_keys | ✓ | 0.95 | `sym_brute_correlation` | Kolodenker et al. — PayBreak (2017); Continella et al. — ShieldFS (2016) |

### 9.1 Recovery values for passed RCs

For each RC that fired, the block below lists the concrete value an operator would feed into the matching decryption strategy. Values are extracted from the captured cryptographic-state and memory-residue records.

#### `RC-04` — `untraced_root_replay`
- **Key bytes**: `0d76b9f786d47506c2ce7f31ee797181762499eee3d0e748c2e3f5e6e7c09e0a`
- **Algorithm**: AES-256, 32 B
- **Source**: `in_buf_length_only+snapshot_extracted`
- **Provenance**: `crypto_3.bin` offset 0 @ buf 0x1d40bf33538
- **Total sym_keys**: 1

#### `RC-05` — `rng_seed_replay`
- **RNG calls (total)**: 21314
- **RNG APIs**: `SystemFunction036`=21279, `BCryptGenRandom`=33, `CryptGenRandom`=2
- **Chain depth**: 21275

#### `RC-06` — `concrete_artifact_to_cipher_id`
- **Decisive artifacts**: 1 decisive cipher artifact: aeskeyfind byte-signature (15 hits)
- **Residue class**: `HIGH`
- **Residue matches**: 0
- **AES key schedules recovered**: 1 distinct
  - `398086f179623df88680ce195839ee88555d59ac92221189f35e62f91aba5708`
- **How to use them**: Each is a candidate AES key located by the key-schedule self-consistency scan. Trial-decrypt the sealed files with it; a wrong key leaves ciphertext entropy unchanged, so a real one is recognisable without a reference copy.
- **Recovery basis**: A captured cipher constant / key-residue signature / family marker pins the cipher/family -- a partial-recovery path (feasibility), not a guaranteed full-key dump

#### `RC-07` — `sym_brute_correlation`
- **Total sym_keys**: 1
- **Keys with captured bytes**: 1
- **Captured key samples**: 
  - `0d76b9f786d47506c2ce7f31ee797181762499eee3d0e748c2e3f5e6e7c09e0a`
- **decryption_essentials.json**: present


### 9.2 Matched evidence per passed RC

Per-primitive observations that satisfied each RC conjunction.

**`RC-04` — untraced_symmetric_key_root**
- `hardcoded_key_ratio_at_least` → 42127/42148=1.00; threshold=0.80
- `hardcoded_key_recoverable` → direct captured key: 1 unique sym keys; threshold 1
- `has_any_event` → hit: BCryptEncrypt, CryptEncrypt

**`RC-05` — weak_predictable_rng_seed**
- `weak_rng_with_keygen` → 1000 rng→keygen path(s); e.g. tag 1→462 via BCryptGenerateSymmetricKey
- `sym_keys_unique_at_least` → 1 unique sym keys; threshold 1

**`RC-06` — decisive_cipher_artifact_captured**
- `decisive_cipher_artifact` → 1 decisive cipher artifact: aeskeyfind byte-signature (15 hits)

**`RC-07` — captured_symmetric_session_keys**
- `captured_symmetric_keys_at_least` → 1 captured sym keys (sym_keys); threshold 1
- `has_any_event` → hit: BCryptEncrypt, CryptEncrypt
- `file_present` → decryption_essentials.json: present via crypto_events_N.jsonl (kinds=kdf,key_export,keygen)


### 9.3 Behavioral evidence (process / network / anti-debug)

Complements §5 (File Operations) with categories that the file-op counters do not cover. Visible regardless of RC fire.

| category | total calls | unique APIs | top APIs (count) |
|---|---:|---:|---|
| Process injection | 0 | 0 | (none observed) |
| C2 network | 0 | 0 | (none observed) |
| Anti-debug / VM detect | 0 | 0 | (none observed) |

> **`NtSetInformationFile`** called `20797` times — §5 `renames` only counts `MoveFileW` + `MoveFileExW`. When invoked with `FileInformationClass = FileRenameInformation`, this is a rename. PinTool does not currently dereference the argument; treat as upper bound on additional raw-API renames.

> **PinTool capture gap**: the categories `C2_Network`, `AntiAnalysis` are not currently hooked by the PinTool instrumentation — `0 observed` here means the API was never called *or* was called but not captured.

### 9.4 Anti-analysis evasion risk

**Status: not evasion-suspected.** The sample ran to completion with encryption activity in this trace (via hot loops and/or CryptoAPI).

- CryptoAPI encryption calls: `234025` (0 = custom in-code cipher)
- File writes: `73235`

## 10. Decryption Tool Synthesis Evidence

Pipeline signals that inform decryptor synthesis: the detected cipher, its round count, and the I/O chunk size.

### 10.1 Cipher detection (from crypto-labelled loops)

- **Status**: `not_detected`
- **Primary cipher**: `no cipher identified` (confidence 0.0)

### 10.2 Round count observation

- **Status**: `not_detected` (no crypto-labeled loops in scored set)

### 10.3 I/O chunk size analysis

- **Status**: `detected`
- writes_total: 73235, deletes_total: 63411
