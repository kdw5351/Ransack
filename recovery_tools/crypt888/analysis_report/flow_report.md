# Ransomware Flow Reconstruction — `trace_Crypt888_recovery_live`
> **session**: `trace_Crypt888_recovery_live` • **family tag**: `crypt888`

---
## Stage 1 — Identity & Execution Quality
| field | value |
|---|---|
| family tag (declared) | `crypt888` |
| session_id | `trace_Crypt888_recovery_live` |
| execution_quality | **encrypted_complete** |
| recovery tier | **RC_MATCHED** (2/7 RC cases matched) |
| `NO_PAYLOAD_RUN` flag | `False` |
| `VALIDATED` flag | `False` _(set only after an offline ≥50% byte-level round-trip)_ |
| primary cipher | **XOR (stream) (heuristic, unconfirmed)** (confidence 0.35) |
| key_chain_depth | 99 |
| runtime (s) | 107.31 _(estimated from trace file timestamps)_ |
| peak working set | ? |
| PIN attach failed | `False` |

## Stage 2 — Initialization
DLL category breakdown:

- **com**: 5 dlls
- **crypto.primitive**: 4 dlls
- **crypto.provider**: 3 dlls
- **fs**: 2 dlls
- **gui**: 9 dlls
- **network**: 4 dlls
- **process**: 3 dlls
- **runtime.cpp**: 1 dlls
- **runtime.crt**: 2 dlls
- **shell**: 3 dlls
- **system.api_core**: 7 dlls
- **system.misc**: 7 dlls

## Stage 3 — Key Root: RNG Sources
Total RNG calls: **53**. Hooked APIs observed:

| RNG API | count |
|---|---:|
| `SystemFunction036` | 53 |

## Stage 4 — Key Derivation Chain
Embedded roots + sinks: **413** (embedded_roots=199, sinks=214). `key_chain_depth = 99` (max nested KDF chain seen). `hardcoded_key_ratio = 1.00` (fraction of sinks without an RNG ancestor — RC-04 indicator).

## Stage 5 — Symmetric Key Inventory
Unique symmetric keys: **1**. Asymmetric key blobs: **0**.

## Stage 6 — Loop Inventory (full ransomware behavior flow)
Total hot loops: **19**, crypto-classified: **3**.
Loop compaction: **18 clusters** across **5 distinct behavior labels**.

### 6.1 Behavior distribution by category (full-flow reconstruction)

| Category | Clusters | Iter weight | Meaning |
|---|---:|---:|---|
| `fallback` | 6 | 19 | Fallback / unclassified loops (no rule fired — likely benign Windows runtime utility) |
| `control_flow` | 6 | 15 | Control flow dispatch (indirect call, virtual table, jump table) |
| `file_io` | 3 | 7 | Filesystem read/write pair (encrypted file output) |
| `crypto` | 2 | 7 | Crypto-labelled loops (AES round/sbox, ChaCha quarter, XOR stream/chain, TEA round, hash compress) |
| `memory_pack` | 1 | 3 | Memory pack/unpack & bit-shuffle (packer stub, struct serialisation) |

### 6.2 Per-category breakdown (which loops actually ran in each category)

#### `fallback` — Fallback / unclassified loops (no rule fired — likely benign Windows runtime utility)

| label | clusters | iters |
|---|---:|---:|
| `unknown.utility` | 6 | 19 |

#### `control_flow` — Control flow dispatch (indirect call, virtual table, jump table)

| label | clusters | iters |
|---|---:|---:|
| `anti.short_loop` | 6 | 15 |

#### `file_io` — Filesystem read/write pair (encrypted file output)

| label | clusters | iters |
|---|---:|---:|
| `fs.read_write_pair` | 3 | 7 |

#### `crypto` — Crypto-labelled loops (AES round/sbox, ChaCha quarter, XOR stream/chain, TEA round, hash compress)

| label | clusters | iters |
|---|---:|---:|
| `crypto.xor_stream` | 2 | 7 |

#### `memory_pack` — Memory pack/unpack & bit-shuffle (packer stub, struct serialisation)

| label | clusters | iters |
|---|---:|---:|
| `memory.bitfield_assemble` | 1 | 3 |

### 6.3 Top 10 scored loops (algorithm identification candidates)

| score | label | iters | header IP | cluster id |
|---:|---|---:|---|---|
| 11 | `crypto.xor_stream` | 3 | `0x41f3a5` | `c6d73c58bf09` |
| 7 | `crypto.xor_stream` | 2 | `0x41ef38` | `2bc3c5a00a2d` |
| 7 | `unknown.utility` | 7 | `0x41899a` | `02b879fa22fc` |
| 7 | `crypto.xor_stream` | 2 | `0x41f3a5` | `c6d73c58bf09` |
| 6 | `fs.read_write_pair` | 3 | `0x417595` | `5d9d0d153e25` |
| 6 | `memory.bitfield_assemble` | 3 | `0x41aae7` | `e9b47097af67` |
| 4 | `fs.read_write_pair` | 2 | `0x41f2fb` | `c1b4888d574e` |
| 4 | `anti.short_loop` | 3 | `0x4153f9` | `2a32f162099a` |
| 4 | `fs.read_write_pair` | 2 | `0x41ac36` | `de113af493a7` |
| 4 | `anti.short_loop` | 3 | `0x41f59e` | `b4b1cbf3a8d7` |

## Stage 7 — Encryption Sink Events
The key/data-flow chain records **214** sink events. Direct API calls hooked: `BCryptEncrypt`=144, `CryptEncrypt`=432, `BCryptExportKey`=0, `CryptExportKey`=0.

## Stage 8 — File-System Operations
| operation | count |
|---|---:|
| writes | 230 |
| reads | 1483 |
| renames | 0 |
| deletes | 108 |

## Stage 9 — Recovery Feasibility
- **Tier**: `RC_MATCHED` · `NO_PAYLOAD_RUN`=False · `VALIDATED`=False
- **Strict cases passed**: 2/7
- **Strict cases fired**: `RC-04`, `RC-07`
- **Memory residue**: class=NONE, matches=0, unique_tags=0, snapshots_scanned=338

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
 R1["CryptAcquireContextA<br/>106 calls"]:::root
 R2["SystemFunction036<br/>53 calls<br/>chain tags=53"]:::root
 SRC -.-> R1
 SRC -.-> R2

 KDF["Key Derivation (observed kinds)"]:::grouphdr
 K1["keygen kind<br/>159 events<br/>BCryptGenerateSymmetricKey (106)<br/>CPDestroyKey (53)"]:::kdf
 K2["kdf/hash kinds<br/>901 events<br/>CryptCreateHash (106)<br/>CryptDeriveKey (106)<br/>CryptDestroyHash (106)"]:::kdf
 KDF -.-> K1
 KDF -.-> K2

 INV["Key Inventory (chain summary)"]:::grouphdr
 I1["depth=99<br/>sym_keys=1 unique<br/>asym_blobs=0"]:::kdf
 I2["embedded_roots: 199<br/>(RC-04 indicator)<br/>top APIs: BCryptGenerateSymmetricKey=54, CPCreateHash=53"]:::antil
 INV -.-> I1
 INV -.-> I2

 LOOPS["Hot Loop Categories (rule-matched)"]:::grouphdr
 LO1["fallback<br/>6 clusters · 19 iters"]:::other
 LO2["control_flow<br/>6 clusters · 15 iters"]:::other
 LF3["file_io<br/>3 clusters · 7 iters"]:::file
 LC4["crypto<br/>2 clusters · 7 iters"]:::cryptol
 LO5["memory_pack<br/>1 clusters · 3 iters"]:::other
 LOOPS -.-> LO1
 LOOPS -.-> LO2
 LOOPS -.-> LF3
 LOOPS -.-> LC4
 LOOPS -.-> LO5

 RULES["Rule Matches"]:::grouphdr
 RX1["inline cipher rule<br/>crypto.xor_stream<br/>(loop-pattern match)"]:::rule
 RULES -.-> RX1

 SINK["Encryption Sinks (observed)"]:::grouphdr
 S1["CryptEncrypt<br/>432 calls"]:::sink
 S2["CPEncrypt<br/>216 calls"]:::sink
 S3["BCryptEncrypt<br/>144 calls"]:::sink
 ST["encryption sinks<br/>214 tagged events"]:::sink
 SINK -.-> S1
 SINK -.-> S2
 SINK -.-> S3
 SINK -.-> ST

 FILES["File-System Effects (observed)"]:::grouphdr
 F1["Delete<br/>108 calls"]:::file
 F2["Read<br/>1,483 calls"]:::file
 F3["Write<br/>230 calls"]:::file
 FILES -.-> F1
 FILES -.-> F2
 FILES -.-> F3

 R1 --> K1
 R2 --> K1
 K1 --> K2
 K2 --> I1
 I1 -.-> I2
 I1 --> LC4
 LC4 --> RX1
 RX1 --> ST
 S1 --> ST
 S2 --> ST
 S3 --> ST
 ST --> F3
 LF3 -.-> F1
 LF3 -.-> F2
 LF3 -.-> F3

 T1["Tier: RC_MATCHED<br/>primary cipher: XOR (stream) (heuristic, unconfirmed)<br/>strict cases: 2/7 passed<br/>VALIDATED: False"]:::tier
 ST --> T1
```

---
_Tree structure is built per-sample from the observed key/data-flow chain, the crypto API/kind tallies, the file-operation counts, and the loop-pattern rule that matched. Nodes that do not appear here were never observed in this trace._
