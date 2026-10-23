# Ransomware Flow Reconstruction — `trace_Razrusheniye_recovery_live`
> **session**: `trace_Razrusheniye_recovery_live` • **family tag**: `razrusheniye`

---
## Stage 1 — Identity & Execution Quality
| field | value |
|---|---|
| family tag (declared) | `razrusheniye` |
| session_id | `trace_Razrusheniye_recovery_live` |
| execution_quality | **encrypted_complete** |
| recovery tier | **RC_MATCHED** (4/7 RC cases matched) |
| `NO_PAYLOAD_RUN` flag | `False` |
| `VALIDATED` flag | `False` _(set only after an offline ≥50% byte-level round-trip)_ |
| primary cipher | **no cipher identified** (confidence 0.0) |
| key_chain_depth | 21275 |
| runtime (s) | 7.69 _(estimated from trace file timestamps)_ |
| peak working set | ? |
| PIN attach failed | `False` |

## Stage 2 — Initialization
DLL category breakdown:

- **com**: 2 dlls
- **crypto.primitive**: 3 dlls
- **crypto.provider**: 3 dlls
- **fs**: 1 dlls
- **gui**: 4 dlls
- **library.unknown**: 1 dlls
- **network**: 17 dlls
- **process**: 1 dlls
- **runtime.cpp**: 1 dlls
- **runtime.crt**: 3 dlls
- **shell**: 3 dlls
- **system.api_core**: 7 dlls
- **system.misc**: 2 dlls

## Stage 3 — Key Root: RNG Sources
Total RNG calls: **21314**. Hooked APIs observed:

| RNG API | count |
|---|---:|
| `BCryptGenRandom` | 33 |
| `SystemFunction036` | 21279 |
| `CryptGenRandom` | 2 |

## Stage 4 — Key Derivation Chain
Embedded roots + sinks: **63567** (embedded_roots=21419, sinks=42148). `key_chain_depth = 21275` (max nested KDF chain seen). `hardcoded_key_ratio = 1.00` (fraction of sinks without an RNG ancestor — RC-04 indicator).

## Stage 5 — Symmetric Key Inventory
Unique symmetric keys: **1**. Asymmetric key blobs: **0**.

## Stage 6 — Loop Inventory (full ransomware behavior flow)
Total hot loops: **18**, crypto-classified: **0**.
Loop compaction: **9 clusters** across **4 distinct behavior labels**.

### 6.1 Behavior distribution by category (full-flow reconstruction)

| Category | Clusters | Iter weight | Meaning |
|---|---:|---:|---|
| `fallback` | 5 | 363 | Fallback / unclassified loops (no rule fired — likely benign Windows runtime utility) |
| `control_flow` | 1 | 9 | Control flow dispatch (indirect call, virtual table, jump table) |
| `file_io` | 2 | 7 | Filesystem read/write pair (encrypted file output) |
| `encoding` | 1 | 3 | Encoding / transcoding loops (base64, hex, URL, custom alphabet) |

### 6.2 Per-category breakdown (which loops actually ran in each category)

#### `fallback` — Fallback / unclassified loops (no rule fired — likely benign Windows runtime utility)

| label | clusters | iters |
|---|---:|---:|
| `unknown.utility` | 5 | 363 |

#### `control_flow` — Control flow dispatch (indirect call, virtual table, jump table)

| label | clusters | iters |
|---|---:|---:|
| `anti.short_loop` | 1 | 9 |

#### `file_io` — Filesystem read/write pair (encrypted file output)

| label | clusters | iters |
|---|---:|---:|
| `fs.read_write_pair` | 2 | 7 |

#### `encoding` — Encoding / transcoding loops (base64, hex, URL, custom alphabet)

| label | clusters | iters |
|---|---:|---:|
| `encoding.base64_pack` | 1 | 3 |

### 6.3 Top 10 scored loops (algorithm identification candidates)

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

## Stage 7 — Encryption Sink Events
The key/data-flow chain records **42148** sink events. Direct API calls hooked: `BCryptEncrypt`=42550, `CryptEncrypt`=127650, `BCryptExportKey`=0, `CryptExportKey`=2.

## Stage 8 — File-System Operations
| operation | count |
|---|---:|
| writes | 73235 |
| reads | 86326 |
| renames | 0 |
| deletes | 63411 |

## Stage 9 — Recovery Feasibility
- **Tier**: `RC_MATCHED` · `NO_PAYLOAD_RUN`=False · `VALIDATED`=False
- **Strict cases passed**: 4/7
- **Strict cases fired**: `RC-04`, `RC-05`, `RC-06`, `RC-07`
- **Memory residue**: class=HIGH, matches=0, unique_tags=0, snapshots_scanned=435

## Stage 10 — Integrated Flow Diagram (Mermaid)

Per-sample evidence tree — every node corresponds to a rule that fired or an API that was actually called in this trace. APIs that were hooked but never invoked are omitted; loop categories with 0 clusters are omitted; file ops with 0 events are omitted.

```mermaid
flowchart TB
 classDef grouphdr fill:#eef2ff,stroke:#7080b0,stroke-width:1px,color:#283050,font-weight:bold
 classDef root fill:#e8f4ff,stroke:#0a4f8f,stroke-width:1.5px,color:#0a3070
 classDef kdf fill:#fff7e0,stroke:#a06b00,stroke-width:1.5px,color:#704800
 classDef cryptol fill:#f0e8ff,stroke:#5a2080,stroke-width:1.5px,color:#3a0e60
 classDef antil fill:#ffeae0,stroke:#b04020,stroke-width:1.5px,color:#702010
 classDef other fill:#f5f5f5,stroke:#707070,stroke-width:1px,color:#404040
 classDef sink fill:#ffe8e8,stroke:#a01010,stroke-width:1.5px,color:#700808
 classDef rule fill:#fffae0,stroke:#8a6500,stroke-width:1.5px,color:#503c00
 classDef file fill:#e8ffe8,stroke:#107010,stroke-width:1.5px,color:#054005
 classDef tier fill:#fff,stroke:#202020,stroke-width:2px,color:#000,font-weight:bold

 SRC["Key Sources (observed)"]:::grouphdr
 R1["CryptAcquireContextA<br/>42,553 calls"]:::root
 R2["SystemFunction036<br/>21,279 calls<br/>chain tags=21279"]:::root
 R3["BCryptGenRandom<br/>33 calls<br/>chain tags=33"]:::root
 R4["CryptGenRandom<br/>2 calls<br/>chain tags=2"]:::root
 R5["CPGenRandom<br/>1 calls<br/>chain tags=1"]:::root
 SRC -.-> R1
 SRC -.-> R2
 SRC -.-> R3
 SRC -.-> R4
 SRC -.-> R5

 KDF["Key Derivation (observed kinds)"]:::grouphdr
 K1["keygen kind<br/>85,105 events<br/>BCryptGenerateSymmetricKey (42,551)<br/>CPDestroyKey (21,276)<br/>CPSetKeyParam (21,275)"]:::kdf
 K2["kdf/hash kinds<br/>361,679 events<br/>CryptCreateHash (42,552)<br/>CryptDeriveKey (42,550)<br/>CryptDestroyHash (42,550)"]:::kdf
 KDF -.-> K1
 KDF -.-> K2

 INV["Key Inventory (chain summary)"]:::grouphdr
 I1["depth=21275<br/>sym_keys=1 unique<br/>asym_blobs=0"]:::kdf
 I2["embedded_roots: 21419<br/>(RC-04 indicator)<br/>top APIs: CPCreateHash=21276, CryptCreateHash=38"]:::antil
 INV -.-> I1
 INV -.-> I2

 LOOPS["Hot Loop Categories (rule-matched)"]:::grouphdr
 LO1["fallback<br/>5 clusters · 363 iters"]:::other
 LO2["control_flow<br/>1 clusters · 9 iters"]:::other
 LF3["file_io<br/>2 clusters · 7 iters"]:::file
 LO4["encoding<br/>1 clusters · 3 iters"]:::other
 LOOPS -.-> LO1
 LOOPS -.-> LO2
 LOOPS -.-> LF3
 LOOPS -.-> LO4

 SINK["Encryption Sinks (observed)"]:::grouphdr
 S1["CryptEncrypt<br/>127,650 calls"]:::sink
 S2["CPEncrypt<br/>63,825 calls"]:::sink
 S3["BCryptEncrypt<br/>42,550 calls"]:::sink
 S4["CryptExportKey (asym)<br/>2 calls"]:::sink
 S5["CPExportKey (asym)<br/>1 calls"]:::sink
 ST["encryption sinks<br/>42,148 tagged events"]:::sink
 SINK -.-> S1
 SINK -.-> S2
 SINK -.-> S3
 SINK -.-> S4
 SINK -.-> S5
 SINK -.-> ST

 FILES["File-System Effects (observed)"]:::grouphdr
 F1["Delete<br/>63,411 calls"]:::file
 F2["Read<br/>86,326 calls"]:::file
 F3["Write<br/>73,235 calls"]:::file
 FILES -.-> F1
 FILES -.-> F2
 FILES -.-> F3

 R1 --> K1
 R2 --> K1
 R3 --> K1
 R4 --> K1
 R5 --> K1
 K1 --> K2
 K2 --> I1
 I1 -.-> I2
 I1 -.-> LO1
 S1 --> ST
 S2 --> ST
 S3 --> ST
 S4 --> ST
 S5 --> ST
 ST --> F3
 LF3 -.-> F1
 LF3 -.-> F2
 LF3 -.-> F3

 T1["Tier: RC_MATCHED<br/>primary cipher: no cipher identified<br/>strict cases: 4/7 passed<br/>VALIDATED: False"]:::tier
 ST --> T1
```

---
_Tree structure is built per-sample from the observed key/data-flow chain, the crypto API/kind tallies, the file-operation counts, and the loop-pattern rule that matched. Nodes that do not appear here were never observed in this trace._
