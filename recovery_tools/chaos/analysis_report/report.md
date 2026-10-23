# RANSACK Evidence: `chaos` / `trace_chaos`

## 1. Identity

| key | value |
|---|---|
| family | `chaos` |
| session_id | `trace_chaos` |
| execution_quality | `encrypted_complete` |
| runtime_sec | `205.92` _(estimated from trace file timestamps)_ |
| crypto_executed | `True` |
| coverage notes | `(none)` |

## 2. Per-Sample Verdict

| metric | result |
|---|---|
| Key Detection | yes |
| File Recoverability | yes |
| Loop-Based Behavior Recovery | no |

## 3. Recovery Assessment

- **Tier**: `RC_MATCHED` (1/7 strict cases passed)
- **`NO_PAYLOAD_RUN`** flag: `False` _(sample never executed an encryption pass — re-run rather than read a vacuous decision)_
- **`VALIDATED`** flag: `False` _(set only after an offline byte-level round-trip recovers ≥50% of captured ciphertexts; never set by this pipeline)_

**Evidence-axis breakdown.** Each row is a primitive an RC case keys on; the values show what the RC conjunction evaluated.

| evidence primitive | observation | which RC keys on it |
|---|---|---|
| `asym_priv_capture` | asym_blobs=0; export_apis=0 | RC-01, RC-02 |
| `memory_residue` | class=NONE, matches=0, snapshots=8541 | RC-02, RC-03, RC-06 |
| `sym_keys_inline` | unique=0 | RC-04, RC-07 |
| `hardcoded_keys` | hardcoded_key_ratio=0.67 | RC-04 |
| `weak_rng` | rng_calls=688302; chain_depth=2792 | RC-05 |
| `key_infra_no_sink` | sinks=19459, embedded_roots=17334 | RC-07 |

## 4. Behaviour Signature (hooked API counts)

| API | count |
|---|---:|
| `SystemFunction036` | 229435 |
| `CryptGenRandom` | 458867 |
| `BCryptEncrypt` | 8658 |
| `CryptEncrypt` | 25974 |
| `NtWriteFile` | 34377 |
| `WriteFile` | 68754 |
| `NtReadFile` | 16107 |
| `ReadFile` | 32214 |
| `MoveFileW` | 16061 |
| `CreateFileW` | 100037 |

## 5. File Operations

| metric | value |
|---|---|
| writes | 103131 |
| reads | 48321 |
| renames | 16061 |
| deletes | 0 |

## 6. Loop Pipeline

| metric | value |
|---|---|
| total hot loops | 5 |
| crypto-labelled loops (among top-10 scored) | 0 |
| loop clusters (distinct labels) | 2 |
| corroborated verdicts | 0 |
| byte-gated verdicts | 0 |
| pattern-only verdicts | 0 |
| downgraded verdicts | 0 |

### 6.1 Cluster compaction by behaviour label

| behaviour label | clusters | iter weight | category |
|---|---:|---:|---|
| `fs.read_write_pair` | 3 | 7 | file_io |
| `unknown.utility` | 2 | 4 | fallback |

### 6.2 Top 10 scored loops

| score | label | iters | header IP | cluster id |
|---:|---|---:|---|---|
| 6 | `fs.read_write_pair` | 3 | `0x7ffb30313c99` | `a1bfca200813` |
| 4 | `fs.read_write_pair` | 2 | `0x7ffb303130a0` | `299e24be3159` |
| 4 | `fs.read_write_pair` | 2 | `0x7ffb303131f7` | `4cdce99a8dd9` |
| 2 | `unknown.utility` | 2 | `0x7ffb303104c0` | `f36071bacae4` |
| 2 | `unknown.utility` | 2 | `0x7ffb30313324` | `a6deeec77545` |

## 7. Memory Residue

| metric | value |
|---|---|
| RSA blobs captured | 0 |
| Sym keys captured (unique hex) | 0 |
| RNG sources | 688302 |
| sinks (chain) | 19459 |
| residue class | NONE |
| residue matches | 0 |
| snapshots scanned | 8541 |

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
- **Total sym_keys**: 0
- **Captured bytes**: 0 (PinTool capture cap)
- **Length-only entries**: (none)
- **Algorithms (inferred)**: (none)
- **decryption_essentials.json**: present


### 9.2 Matched evidence per passed RC

Per-primitive observations that satisfied each RC conjunction.

**`RC-07` — captured_symmetric_session_keys**
- `captured_symmetric_keys_at_least` → 8192 captured sym keys (wrapped-key sink_plaintext); threshold 1
- `has_any_event` → hit: BCryptEncrypt, CryptEncrypt
- `file_present` → decryption_essentials.json: present via crypto_events_N.jsonl (kinds=key_import,keygen)


### 9.3 Behavioral evidence (process / network / anti-debug)

Complements §5 (File Operations) with categories that the file-op counters do not cover. Visible regardless of RC fire.

| category | total calls | unique APIs | top APIs (count) |
|---|---:|---:|---|
| Process injection | 0 | 0 | (none observed) |
| C2 network | 0 | 0 | (none observed) |
| Anti-debug / VM detect | 0 | 0 | (none observed) |

> **`NtSetInformationFile`** called `64835` times — §5 `renames` only counts `MoveFileW` + `MoveFileExW`. When invoked with `FileInformationClass = FileRenameInformation`, this is a rename. PinTool does not currently dereference the argument; treat as upper bound on additional raw-API renames.

> **PinTool capture gap**: the categories `C2_Network`, `AntiAnalysis` are not currently hooked by the PinTool instrumentation — `0 observed` here means the API was never called *or* was called but not captured.

### 9.4 Anti-analysis evasion risk

**Status: not evasion-suspected.** The sample ran to completion with encryption activity in this trace (via hot loops and/or CryptoAPI).

- CryptoAPI encryption calls: `47619` (0 = custom in-code cipher)
- File writes: `103131`

## 10. Decryption Tool Synthesis Evidence

Pipeline signals that inform decryptor synthesis: the detected cipher, its round count, and the I/O chunk size.

### 10.1 Cipher detection (from crypto-labelled loops)

- **Status**: `not_detected`
- **Primary cipher**: `no cipher identified` (confidence 0.0)

### 10.2 Round count observation

- **Status**: `not_detected` (no crypto-labeled loops in scored set)

### 10.3 I/O chunk size analysis

- **Status**: `detected`
- writes_total: 103131, deletes_total: 0
