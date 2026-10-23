# RANSACK Evidence: `makop` / `trace_makop`

## 1. Identity

| key | value |
|---|---|
| family | `makop` |
| session_id | `trace_makop` |
| execution_quality | `encrypted_complete` |
| runtime_sec | `510.0` _(on-VM)_ |
| crypto_executed | `True` |
| coverage notes | `(none)` |

## 2. Per-Sample Verdict

| metric | result |
|---|---|
| Key Detection | yes |
| File Recoverability | yes |
| Loop-Based Behavior Recovery | no |

## 3. Recovery Assessment

- **Tier**: `RC_MATCHED` (3/7 strict cases passed)
- **`NO_PAYLOAD_RUN`** flag: `False` _(sample never executed an encryption pass — re-run rather than read a vacuous decision)_
- **`VALIDATED`** flag: `False` _(set only after an offline byte-level round-trip recovers ≥50% of captured ciphertexts; never set by this pipeline)_

**Evidence-axis breakdown.** Each row is a primitive an RC case keys on; the values show what the RC conjunction evaluated.

| evidence primitive | observation | which RC keys on it |
|---|---|---|
| `asym_priv_capture` | asym_blobs=0; export_apis=0 | RC-01, RC-02 |
| `memory_residue` | class=HIGH, matches=0, snapshots=96 | RC-02, RC-03, RC-06 |
| `sym_keys_inline` | unique=1 | RC-04, RC-07 |
| `hardcoded_keys` | hardcoded_key_ratio=0.03 | RC-04 |
| `weak_rng` | rng_calls=20659; chain_depth=20648 | RC-05 |
| `key_infra_no_sink` | sinks=28929, embedded_roots=14547 | RC-07 |

## 4. Behaviour Signature (hooked API counts)

| API | count |
|---|---:|
| `SystemFunction036` | 6887 |
| `CryptGenRandom` | 13772 |
| `BCryptEncrypt` | 27536 |
| `CryptEncrypt` | 55072 |
| `NtWriteFile` | 67182 |
| `WriteFile` | 134362 |
| `NtReadFile` | 13570 |
| `ReadFile` | 27138 |
| `MoveFileW` | 6782 |
| `CreateFileW` | 54719 |

## 5. File Operations

| metric | value |
|---|---|
| writes | 201544 |
| reads | 40708 |
| renames | 6782 |
| deletes | 0 |

## 6. Loop Pipeline

| metric | value |
|---|---|
| total hot loops | 48 |
| crypto-labelled loops (among top-10 scored) | 0 |
| loop clusters (distinct labels) | 3 |
| corroborated verdicts | 0 |
| byte-gated verdicts | 0 |
| pattern-only verdicts | 0 |
| downgraded verdicts | 0 |

### 6.1 Cluster compaction by behaviour label

| behaviour label | clusters | iter weight | category |
|---|---:|---:|---|
| `unknown.utility` | 13 | 101 | fallback |
| `anti.short_loop` | 3 | 61 | control_flow |
| `fs.read_write_pair` | 5 | 11 | file_io |

### 6.2 Top 10 scored loops

| score | label | iters | header IP | cluster id |
|---:|---|---:|---|---|
| 22 | `unknown.utility` | 22 | `0x403f35` | `a76e1cce36c3` |
| 21 | `unknown.utility` | 21 | `0x402370` | `7a80f019490a` |
| 6 | `fs.read_write_pair` | 3 | `0x404e00` | `366585cc5203` |
| 5 | `unknown.utility` | 5 | `0x402050` | `525874fbb885` |
| 4 | `anti.short_loop` | 3 | `0x402170` | `af102ccddca5` |
| 4 | `anti.short_loop` | 3 | `0x4040c3` | `16e104041d4f` |
| 4 | `anti.short_loop` | 3 | `0x4040d0` | `af102ccddca5` |
| 4 | `anti.short_loop` | 3 | `0x4036d2` | `16e104041d4f` |
| 4 | `unknown.utility` | 4 | `0x403ff3` | `ff04f1172f0d` |
| 4 | `anti.short_loop` | 3 | `0x403492` | `94557213cbad` |

## 7. Memory Residue

| metric | value |
|---|---|
| RSA blobs captured | 0 |
| Sym keys captured (unique hex) | 1 |
| RNG sources | 20659 |
| sinks (chain) | 28929 |
| residue class | HIGH |
| residue matches | 0 |
| snapshots scanned | 96 |

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

- **Passed**: 3 / 7
- **Recoverable (strict)**: Yes

| case | name | passed | confidence | strategy | key literature |
|---|---|:---:|---:|---|---|
| `RC-01` | rsa_private_blob_exported_full | — | 0.98 | `asym_priv_universal` | Suiche, M. — wanakiwi technical writeup (2017); Trellix — Avaddon (2021) |
| `RC-02` | per_run_rsa_keypair_in_heap | — | 0.85 | `memory_residue_scan` | Bajpai & Enbody — Dissecting .NET Ransom (2018); Kolodenker et al. — PayBreak (2017) |
| `RC-03` | memory_residue_prime_scan_cryptoapi | — | 0.55 | `memory_residue_scan` | Suiche, M. — WannaCry: Decrypting files (2017); Guinet, A. — wannakey (2017) |
| `RC-04` | untraced_symmetric_key_root | — | 0.95 | `untraced_root_replay` | Bajpai & Enbody — Empirical Study of Key (2020); Securelist — CryptoLocker (2014) |
| `RC-05` | weak_predictable_rng_seed | ✓ | 0.7 | `rng_seed_replay` | AVAST Decoded — Bart ransomware decryptor (2016); Hasherezade — Petya v1 Salsa20 (2016) |
| `RC-06` | decisive_cipher_artifact_captured | ✓ | 0.65 | `concrete_artifact_to_cipher_id` | Wheeler & Needham — TEA (1994); Halderman et al. — Lest We Remember (2008) |
| `RC-07` | captured_symmetric_session_keys | ✓ | 0.95 | `sym_brute_correlation` | Kolodenker et al. — PayBreak (2017); Continella et al. — ShieldFS (2016) |

### 9.1 Recovery values for passed RCs

For each RC that fired, the block below lists the concrete value an operator would feed into the matching decryption strategy. Values are extracted from the captured cryptographic-state and memory-residue records.

#### `RC-05` — `rng_seed_replay`
- **RNG calls (total)**: 20659
- **RNG APIs**: `CryptGenRandom`=13772, `SystemFunction036`=6887
- **Chain depth**: 20648

#### `RC-06` — `concrete_artifact_to_cipher_id`
- **Decisive artifacts**: 1 decisive cipher artifact: aeskeyfind byte-signature (7 hits)
- **Residue class**: `HIGH`
- **Residue matches**: 0
- **Recovery basis**: A captured cipher constant / key-residue signature / family marker pins the cipher/family -- a partial-recovery path (feasibility), not a guaranteed full-key dump

#### `RC-07` — `sym_brute_correlation`
- **Total sym_keys**: 1
- **Keys with captured bytes**: 1
- **Captured key samples**: 
  - `98dfee9e13ad42a6789c97250080fdf90e2c4187e9108518e44116f5be1b9b9f`
- **decryption_essentials.json**: present


### 9.2 Matched evidence per passed RC

Per-primitive observations that satisfied each RC conjunction.

**`RC-05` — weak_predictable_rng_seed**
- `weak_rng_with_keygen` → 1000 rng→keygen path(s); e.g. tag 131087→131092 via CPSetKeyParam
- `sym_keys_unique_at_least` → 1 unique sym keys; threshold 1

**`RC-06` — decisive_cipher_artifact_captured**
- `decisive_cipher_artifact` → 1 decisive cipher artifact: aeskeyfind byte-signature (7 hits)

**`RC-07` — captured_symmetric_session_keys**
- `sym_keys_unique_at_least` → 1 unique sym keys; threshold 1
- `has_any_event` → hit: BCryptDecrypt, BCryptEncrypt, CryptDecrypt, CryptEncrypt
- `file_present` → decryption_essentials.json: present via crypto_events_N.jsonl (kinds=key_import,keygen)


### 9.3 Behavioral evidence (process / network / anti-debug)

Complements §5 (File Operations) with categories that the file-op counters do not cover. Visible regardless of RC fire.

| category | total calls | unique APIs | top APIs (count) |
|---|---:|---:|---|
| Process injection | 0 | 0 | (none observed) |
| C2 network | 0 | 0 | (none observed) |
| Anti-debug / VM detect | 0 | 0 | (none observed) |

> **`NtSetInformationFile`** called `53811` times — §5 `renames` only counts `MoveFileW` + `MoveFileExW`. When invoked with `FileInformationClass = FileRenameInformation`, this is a rename. PinTool does not currently dereference the argument; treat as upper bound on additional raw-API renames.

> **PinTool capture gap**: the categories `C2_Network`, `AntiAnalysis` are not currently hooked by the PinTool instrumentation — `0 observed` here means the API was never called *or* was called but not captured.

### 9.4 Anti-analysis evasion risk

**Status: not evasion-suspected.** The sample ran to completion with encryption activity in this trace (via hot loops and/or CryptoAPI).

- CryptoAPI encryption calls: `116160` (0 = custom in-code cipher)
- File writes: `201544`

## 10. Decryption Tool Synthesis Evidence

Pipeline signals that inform decryptor synthesis: the detected cipher, its round count, and the I/O chunk size.

### 10.1 Cipher detection (from crypto-labelled loops)

- **Status**: `not_detected`
- **Primary cipher**: `no cipher identified` (confidence 0.0)

### 10.2 Round count observation

- **Status**: `not_detected` (no crypto-labeled loops in scored set)

### 10.3 I/O chunk size analysis

- **Status**: `detected`
- writes_total: 201544, deletes_total: 0
