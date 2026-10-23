# RANSACK Evidence: `azzasec` / `trace_AzzaSec_recovery_live`

## 1. Identity

| key | value |
|---|---|
| family | `azzasec` |
| session_id | `trace_AzzaSec_recovery_live` |
| execution_quality | `pin_attach_failed` |
| runtime_sec | `456.0` _(on-VM)_ |
| crypto_executed | `False` |
| coverage notes | `no_crypto_events, no_io_events` |

## 2. Per-Sample Verdict

| metric | result |
|---|---|
| Key Detection | no |
| File Recoverability | no |
| Loop-Based Behavior Recovery | no |

## 3. Recovery Assessment

- **Tier**: `NO_PAYLOAD_RUN` (0/7 strict cases passed)
- **`NO_PAYLOAD_RUN`** flag: `True` _(sample never executed an encryption pass — re-run rather than read a vacuous decision)_
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
| *(no hooked API observed)* | 0 |

## 5. File Operations

| metric | value |
|---|---|
| writes | 0 |
| reads | 0 |
| renames | 0 |
| deletes | 0 |

## 6. Loop Pipeline

| metric | value |
|---|---|
| total hot loops | 0 |
| crypto-labelled loops (among top-10 scored) | 0 |
| loop clusters (distinct labels) | 0 |
| corroborated verdicts | 0 |
| byte-gated verdicts | 0 |
| pattern-only verdicts | 0 |
| downgraded verdicts | 0 |

### 6.1 Cluster compaction by behaviour label

| behaviour label | clusters | iter weight | category |
|---|---:|---:|---|

### 6.2 Top 10 scored loops

| score | label | iters | header IP | cluster id |
|---:|---|---:|---|---|

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
| `EXEC_QUALITY_NO_PAYLOAD` | ✓ | Increase the execution-time budget; confirm the tracer attached to the correct process; check for anti-debug bailout. |
| `ANTI_ANALYSIS_LOOPS_DETECTED` | — | Run with anti-instrumentation countermeasures; intercept anti-debug probes (IsDebuggerPresent, NtQueryInformationProcess) and return benign values. |
| `SAMPLE_IMG_NOT_INSTRUMENTED` | ✓ | Add Windows late-load image hooks (NtMapViewOfSection, LdrLoadDll) so image-mapping patterns get instrumented. |
| `KEY_CHAIN_DEPTH_ZERO_WITH_SIGNALS` | — | A memory-copy/key-duplication primitive (memcpy, RtlMoveMemory, BCryptDuplicateKey) was not followed in the key-derivation chain, which can over-credit RC-04. |
| `PYD_NOT_REGISTERED` | — | PyCryptodome's compiled crypto extensions (.pyd) were not registered as crypto sinks, so the module surfaced no key sink. |
| `RESIDUE_DRY_WITH_RNG` | — | RNG fired but no residue snapshot matched — the key was likely zeroed mid-encryption. |

## 9. Strict Recovery Cases (RC-01..RC-07)

- **Passed**: 0 / 7
- **Recoverable (strict)**: No

| case | name | passed | confidence | strategy | key literature |
|---|---|:---:|---:|---|---|
| `RC-01` | rsa_private_blob_exported_full | — | 0.98 | `asym_priv_universal` | Suiche, M. — wanakiwi technical writeup (2017); Trellix — Avaddon (2021) |
| `RC-02` | per_run_rsa_keypair_in_heap | — | 0.85 | `memory_residue_scan` | Bajpai & Enbody — Dissecting .NET Ransom (2018); Kolodenker et al. — PayBreak (2017) |
| `RC-03` | memory_residue_prime_scan_cryptoapi | — | 0.55 | `memory_residue_scan` | Suiche, M. — WannaCry: Decrypting files (2017); Guinet, A. — wannakey (2017) |
| `RC-04` | untraced_symmetric_key_root | — | 0.95 | `untraced_root_replay` | Bajpai & Enbody — Empirical Study of Key (2020); Securelist — CryptoLocker (2014) |
| `RC-05` | weak_predictable_rng_seed | — | 0.7 | `rng_seed_replay` | AVAST Decoded — Bart ransomware decryptor (2016); Hasherezade — Petya v1 Salsa20 (2016) |
| `RC-06` | decisive_cipher_artifact_captured | — | 0.65 | `concrete_artifact_to_cipher_id` | Wheeler & Needham — TEA (1994); Halderman et al. — Lest We Remember (2008) |
| `RC-07` | captured_symmetric_session_keys | — | 0.95 | `sym_brute_correlation` | Kolodenker et al. — PayBreak (2017); Continella et al. — ShieldFS (2016) |

### 9.1 Behavioral evidence (process / network / anti-debug)

Complements §5 (File Operations) with categories that the file-op counters do not cover. Visible regardless of RC fire.

| category | total calls | unique APIs | top APIs (count) |
|---|---:|---:|---|
| Process injection | 0 | 0 | (none observed) |
| C2 network | 0 | 0 | (none observed) |
| Anti-debug / VM detect | 0 | 0 | (none observed) |

> **PinTool capture gap**: the categories `C2_Network`, `AntiAnalysis` are not currently hooked by the PinTool instrumentation — `0 observed` here means the API was never called *or* was called but not captured.

### 9.2 Anti-analysis evasion risk

**EVASION SUSPECTED** — this sample exhibits no (or near-zero) actual encryption activity despite running to completion under PinTool. Likely cause: anti-DBI / anti-VM bailout (sample detects instrumentation and silently exits or sleeps to time out the harness).

- **Trigger flags**: `no_encryption_observed`, `no_file_writes`
- Encryption calls observed: `0`
- File writes observed: `0`
- RNG calls: `0` (ratio 0.00)
- Sleep / delay calls: `0`

## 10. Decryption Tool Synthesis Evidence

Pipeline signals that inform decryptor synthesis: the detected cipher, its round count, and the I/O chunk size.

### 10.1 Cipher detection (from crypto-labelled loops)

- **Status**: `not_detected`
- **Primary cipher**: `no cipher identified` (confidence 0.0)

### 10.2 Round count observation

- **Status**: `not_detected` (no crypto-labeled loops in scored set)

### 10.3 I/O chunk size analysis

- **Status**: `not_detected`
- writes_total: 0, deletes_total: 0
