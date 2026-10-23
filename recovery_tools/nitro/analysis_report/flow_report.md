# Ransomware Flow Reconstruction — `trace_Nitro_32bit_live`
> **session**: `trace_Nitro_32bit_live` • **family tag**: `nitro`

---
## Stage 1 — Identity & Execution Quality
| field | value |
|---|---|
| family tag (declared) | `nitro` |
| session_id | `trace_Nitro_32bit_live` |
| execution_quality | **encrypted_partial** |
| recovery tier | **INFEASIBLE** (0/7 RC cases matched) |
| `NO_PAYLOAD_RUN` flag | `False` |
| `VALIDATED` flag | `False` _(set only after an offline ≥50% byte-level round-trip)_ |
| primary cipher | **no cipher identified** (confidence 0.0) |
| key_chain_depth | 24991 |
| runtime (s) | 418.77 _(estimated from trace file timestamps)_ |
| peak working set | ? |
| PIN attach failed | `False` |

## Stage 2 — Initialization
DLL category breakdown:

- *(no DLLs categorised)*

## Stage 3 — Key Root: RNG Sources
Total RNG calls: **103**. Hooked APIs observed:

| RNG API | count |
|---|---:|
| `SystemFunction036` | 35 |
| `CryptGenRandom` | 68 |

## Stage 4 — Key Derivation Chain
Embedded roots + sinks: **94329** (embedded_roots=94329, sinks=0). `key_chain_depth = 24991` (max nested KDF chain seen). `hardcoded_key_ratio = 0.00` (fraction of sinks without an RNG ancestor — RC-04 indicator).

## Stage 5 — Symmetric Key Inventory
Unique symmetric keys: **0**. Asymmetric key blobs: **0**.

## Stage 6 — Loop Inventory (full ransomware behavior flow)
Total hot loops: **1**, crypto-classified: **0**.
Loop compaction: **1 clusters** across **1 distinct behavior labels**.

### 6.1 Behavior distribution by category (full-flow reconstruction)

| Category | Clusters | Iter weight | Meaning |
|---|---:|---:|---|
| `fallback` | 1 | 2 | Fallback / unclassified loops (no rule fired — likely benign Windows runtime utility) |

### 6.2 Per-category breakdown (which loops actually ran in each category)

#### `fallback` — Fallback / unclassified loops (no rule fired — likely benign Windows runtime utility)

| label | clusters | iters |
|---|---:|---:|
| `unknown.utility` | 1 | 2 |

### 6.3 Top 10 scored loops (algorithm identification candidates)

| score | label | iters | header IP | cluster id |
|---:|---|---:|---|---|
| 2 | `unknown.utility` | 2 | `0x7b650c77` | `0325885a2bec` |

## Stage 7 — Encryption Sink Events
The key/data-flow chain records **0** sink events. Direct API calls hooked: `BCryptEncrypt`=0, `CryptEncrypt`=0, `BCryptExportKey`=0, `CryptExportKey`=0.

## Stage 8 — File-System Operations
| operation | count |
|---|---:|
| writes | 27 |
| reads | 54 |
| renames | 0 |
| deletes | 0 |

## Stage 9 — Recovery Feasibility
- **Tier**: `INFEASIBLE` · `NO_PAYLOAD_RUN`=False · `VALIDATED`=False
- **Strict cases passed**: 0/7
- **Strict cases fired**: (none)
- **Memory residue**: class=NONE, matches=0, unique_tags=0, snapshots_scanned=0

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
 R1["CryptGenRandom<br/>68 calls<br/>chain tags=68"]:::root
 R2["SystemFunction036<br/>35 calls<br/>chain tags=35"]:::root
 R3["CPGenRandom<br/>34 calls<br/>chain tags=34"]:::root
 R4["BCryptCloseAlgorithmProvider<br/>2 calls<br/>chain tags=2"]:::root
 SRC -.-> R1
 SRC -.-> R2
 SRC -.-> R3
 SRC -.-> R4

 KDF["Key Derivation (observed kinds)"]:::grouphdr
 K1["keygen kind<br/>5 events<br/>BCryptOpenAlgorithmProvider (3)<br/>CryptAcquireContextW (2)<br/>CryptAcquireContextA (1)"]:::kdf
 K2["kdf/hash kinds<br/>861,800 events<br/>CryptHashData (219,376)<br/>CryptGetHashParam (125,345)<br/>CPHashData (109,688)"]:::kdf
 KDF -.-> K1
 KDF -.-> K2

 INV["Key Inventory (chain summary)"]:::grouphdr
 I1["depth=24991<br/>sym_keys=0 unique<br/>asym_blobs=0"]:::kdf
 I2["embedded_roots: 94329<br/>(RC-04 indicator)<br/>top APIs: CryptCreateHash=62680, CPCreateHash=31340"]:::antil
 INV -.-> I1
 INV -.-> I2

 LOOPS["Hot Loop Categories (rule-matched)"]:::grouphdr
 LO1["fallback<br/>1 clusters · 2 iters"]:::other
 LOOPS -.-> LO1

 FILES["File-System Effects (observed)"]:::grouphdr
 F1["Read<br/>54 calls"]:::file
 F2["Write<br/>27 calls"]:::file
 FILES -.-> F1
 FILES -.-> F2

 R1 --> K1
 R2 --> K1
 R3 --> K1
 R4 --> K1
 K1 --> K2
 K2 --> I1
 I1 -.-> I2
 I1 -.-> LO1

 T1["Tier: INFEASIBLE<br/>primary cipher: no cipher identified<br/>strict cases: 0/7 passed<br/>VALIDATED: False"]:::tier
 I1 --> T1
```

---
_Tree structure is built per-sample from the observed key/data-flow chain, the crypto API/kind tallies, the file-operation counts, and the loop-pattern rule that matched. Nodes that do not appear here were never observed in this trace._
