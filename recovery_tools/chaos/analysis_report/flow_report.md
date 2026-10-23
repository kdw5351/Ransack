# Ransomware Flow Reconstruction — `trace_chaos`
> **session**: `trace_chaos` • **family tag**: `chaos`

---
## Stage 1 — Identity & Execution Quality
| field | value |
|---|---|
| family tag (declared) | `chaos` |
| session_id | `trace_chaos` |
| execution_quality | **encrypted_complete** |
| recovery tier | **RC_MATCHED** (1/7 RC cases matched) |
| `NO_PAYLOAD_RUN` flag | `False` |
| `VALIDATED` flag | `False` _(set only after an offline ≥50% byte-level round-trip)_ |
| primary cipher | **no cipher identified** (confidence 0.0) |
| key_chain_depth | 2792 |
| runtime (s) | 205.92 _(estimated from trace file timestamps)_ |
| peak working set | ? |
| PIN attach failed | `False` |

## Stage 2 — Initialization
DLL category breakdown:

- **com**: 3 dlls
- **crypto.primitive**: 3 dlls
- **crypto.provider**: 3 dlls
- **gui**: 4 dlls
- **library.unknown**: 1 dlls
- **runtime.cpp**: 1 dlls
- **runtime.crt**: 5 dlls
- **runtime.dotnet**: 5 dlls
- **shell**: 1 dlls
- **system.api_core**: 7 dlls
- **system.misc**: 2 dlls

## Stage 3 — Key Root: RNG Sources
Total RNG calls: **688302**. Hooked APIs observed:

| RNG API | count |
|---|---:|
| `SystemFunction036` | 229435 |
| `CryptGenRandom` | 458867 |

## Stage 4 — Key Derivation Chain
Embedded roots + sinks: **36793** (embedded_roots=17334, sinks=19459). `key_chain_depth = 2792` (max nested KDF chain seen). `hardcoded_key_ratio = 0.67` (fraction of sinks without an RNG ancestor — RC-04 indicator).

## Stage 5 — Symmetric Key Inventory
Unique symmetric keys: **0**. Asymmetric key blobs: **0**.

## Stage 6 — Loop Inventory (full ransomware behavior flow)
Total hot loops: **5**, crypto-classified: **0**.
Loop compaction: **5 clusters** across **2 distinct behavior labels**.

### 6.1 Behavior distribution by category (full-flow reconstruction)

| Category | Clusters | Iter weight | Meaning |
|---|---:|---:|---|
| `file_io` | 3 | 7 | Filesystem read/write pair (encrypted file output) |
| `fallback` | 2 | 4 | Fallback / unclassified loops (no rule fired — likely benign Windows runtime utility) |

### 6.2 Per-category breakdown (which loops actually ran in each category)

#### `file_io` — Filesystem read/write pair (encrypted file output)

| label | clusters | iters |
|---|---:|---:|
| `fs.read_write_pair` | 3 | 7 |

#### `fallback` — Fallback / unclassified loops (no rule fired — likely benign Windows runtime utility)

| label | clusters | iters |
|---|---:|---:|
| `unknown.utility` | 2 | 4 |

### 6.3 Top 10 scored loops (algorithm identification candidates)

| score | label | iters | header IP | cluster id |
|---:|---|---:|---|---|
| 6 | `fs.read_write_pair` | 3 | `0x7ffb30313c99` | `a1bfca200813` |
| 4 | `fs.read_write_pair` | 2 | `0x7ffb303130a0` | `299e24be3159` |
| 4 | `fs.read_write_pair` | 2 | `0x7ffb303131f7` | `4cdce99a8dd9` |
| 2 | `unknown.utility` | 2 | `0x7ffb303104c0` | `f36071bacae4` |
| 2 | `unknown.utility` | 2 | `0x7ffb30313324` | `a6deeec77545` |

## Stage 7 — Encryption Sink Events
The key/data-flow chain records **19459** sink events. Direct API calls hooked: `BCryptEncrypt`=8658, `CryptEncrypt`=25974, `BCryptExportKey`=0, `CryptExportKey`=0.

## Stage 8 — File-System Operations
| operation | count |
|---|---:|
| writes | 103131 |
| reads | 48321 |
| renames | 16061 |
| deletes | 0 |

## Stage 9 — Recovery Feasibility
- **Tier**: `RC_MATCHED` · `NO_PAYLOAD_RUN`=False · `VALIDATED`=False
- **Strict cases passed**: 1/7
- **Strict cases fired**: `RC-07`
- **Memory residue**: class=NONE, matches=0, unique_tags=0, snapshots_scanned=8541

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
 R1["CryptGenRandom<br/>458,867 calls<br/>chain tags=458867"]:::root
 R2["SystemFunction036<br/>229,435 calls<br/>chain tags=229435"]:::root
 R3["CPGenRandom<br/>229,433 calls<br/>chain tags=229433"]:::root
 R4["CryptAcquireContextW<br/>2 calls"]:::root
 R5["CryptAcquireContextA<br/>1 calls"]:::root
 SRC -.-> R1
 SRC -.-> R2
 SRC -.-> R3
 SRC -.-> R4
 SRC -.-> R5

 KDF["Key Derivation (observed kinds)"]:::grouphdr
 K1["keygen kind<br/>4,329 events<br/>CryptImportKey (8,658)<br/>BCryptImportKeyPair (4,329)<br/>CPDestroyKey (4,329)"]:::kdf
 K3["key import<br/>17,316 events<br/>—"]:::kdf
 KDF -.-> K1
 KDF -.-> K3

 INV["Key Inventory (chain summary)"]:::grouphdr
 I1["depth=2792<br/>sym_keys=0 unique<br/>asym_blobs=0"]:::kdf
 I2["embedded_roots: 17334<br/>(RC-04 indicator)<br/>top APIs: CPDestroyKey=4329, CryptImportKey=18"]:::antil
 INV -.-> I1
 INV -.-> I2

 LOOPS["Hot Loop Categories (rule-matched)"]:::grouphdr
 LF1["file_io<br/>3 clusters · 7 iters"]:::file
 LO2["fallback<br/>2 clusters · 4 iters"]:::other
 LOOPS -.-> LF1
 LOOPS -.-> LO2

 SINK["Encryption Sinks (observed)"]:::grouphdr
 S1["CryptEncrypt<br/>25,974 calls"]:::sink
 S2["CPEncrypt<br/>12,987 calls"]:::sink
 S3["BCryptEncrypt<br/>8,658 calls"]:::sink
 ST["encryption sinks<br/>19,459 tagged events"]:::sink
 SINK -.-> S1
 SINK -.-> S2
 SINK -.-> S3
 SINK -.-> ST

 FILES["File-System Effects (observed)"]:::grouphdr
 F1["Rename<br/>16,061 calls"]:::file
 F2["Read<br/>48,321 calls"]:::file
 F3["Write<br/>103,131 calls"]:::file
 FILES -.-> F1
 FILES -.-> F2
 FILES -.-> F3

 R1 --> K1
 R2 --> K1
 R3 --> K1
 R4 --> K1
 R5 --> K1
 K1 --> K3
 K3 --> I1
 I1 -.-> I2
 I1 -.-> LF1
 S1 --> ST
 S2 --> ST
 S3 --> ST
 ST --> F3
 LF1 -.-> F1
 LF1 -.-> F2
 LF1 -.-> F3

 T1["Tier: RC_MATCHED<br/>primary cipher: no cipher identified<br/>strict cases: 1/7 passed<br/>VALIDATED: False"]:::tier
 ST --> T1
```

---
_Tree structure is built per-sample from the observed key/data-flow chain, the crypto API/kind tallies, the file-operation counts, and the loop-pattern rule that matched. Nodes that do not appear here were never observed in this trace._
