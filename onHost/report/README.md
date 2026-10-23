# onHost/report/ — Report packager

Renders the paper artefacts from `analysis_report.json`.

## Files

| File | Role |
|---|---|
| `schema.py` | `adapt(ar, trace_root, dll_roles)` — flattens `analysis_report.json` into the unified `view` dict consumed by all three Markdown writers and `sample_view.json`. Includes the recovery-value extractor, the behavioural-evidence sweep, and the evasion detector that back the §9 subsections. |
| `writers.py` | Three Markdown renderers: `flow_report.md`, `report.md`, `unified_report.md`. |
| `generate.py` | Driver — discovers `_analysis/proc_*/_detail/analysis_report.json`, calls `adapt`, writes the five artefacts under `_paper_report/`. |

## Artefacts emitted

For every sample, `_paper_report/` is written next to the trace
directory and contains:

```
_paper_report/
├── README.md             Per-sample index
├── flow_report.md        Stage-by-stage runtime flow
├── report.md             Recovery-focused report (the paper's recovery cases)
├── unified_report.md     Single-page summary
└── sample_view.json      Machine-readable view (same `view` the writers consume)
```

## report.md sections

| §  | Content |
|---|---|
| 1–2 | Identity; the three per-sample paper metrics (key detection, file recoverability, loop-based behaviour recovery) |
| 3   | Recovery assessment — tier, `NO_PAYLOAD_RUN` / `VALIDATED` flags, evidence-axis breakdown |
| 4–5 | Hooked-API behaviour signature; file-operation counts |
| 6   | Loop pipeline — behaviour-label clusters and top-scored loops |
| 7–8 | Memory residue; detection gaps (paper §V-A taxonomy) |
| 9   | RC verdicts (RC-01 … RC-07) |
| 10  | Decryption-tool synthesis evidence — cipher, round count, I/O chunk size |
| References | Per-claim citation map |

`report.md` ends at §10. Corpus-level statistics are not per-sample — they live in
`paper_aggregate.md`, which `generate.py` writes from the `sample_view.json` files across traces.

### §9 subsection numbering

`writers.py` numbers the §9 subsections with a running counter, so a block's number depends on
which blocks precede it:

| Block | Emitted | Number |
|---|---|---|
| Recovery values for passed RCs — key hex / blob hex / decryptor URL, with snapshot provenance | only when an RC fires | §9.1 |
| Matched evidence per passed RC — the per-primitive observations satisfying its conjunction | only when an RC fires | §9.2 |
| Behavioural evidence (process injection, C2 network, anti-debug) | always | §9.3 |
| Anti-analysis evasion risk | always | §9.4 |

With zero passed cases the first two are skipped and the last two render as §9.1 and §9.2. The
bundled `example_trace` (0/7) is exactly that case — do not treat its numbering as a regression.
