# Evaluation data

This directory contains the released data for the RANSACK evaluation.

- `samples.csv` is the corpus manifest for all **6,818 evaluated samples**. It identifies each sample by SHA-256 and retains the per-sample summary fields used to derive the manifest-based aggregate results.
- Its execution outcomes comprise **6,326 Captured evidence**, **100 Environment failure**, and **392 Blocked before detonation** entries.
- `recovery_constructions.xlsx`, `retained_evidence.xlsx`, and `static_comparison.xlsx` hold the per-capture and per-family records behind the reported figures, so a number can be traced to the rows it was computed from. `static_comparison.xlsx` carries one row per evidence-bearing capture with its YARA hit count, capa capability count and status, and packing classification; `retained_evidence.xlsx` carries the algorithm-claim and predicate adjudication for the reviewed captures with the supporting artifact-level checks; `recovery_constructions.xlsx` carries the separate-infection results for all thirteen families. Corpus-wide sheets reflect the measurements taken before the implementation corrections, and the verification sheets reflect the corrected implementation on the same reviewed captures.
- `reports/` contains compact `sample_view.json` records for all **6,326 samples labeled Captured evidence**. These are per-sample summary/source views, not complete rendered report sets.
- Complete `report.md`, `flow_report.md`, `unified_report.md`, and `sample_view.json` sets for the **thirteen constructive recoveries** are stored under `../recovery_tools/<family>/analysis_report/`.
- `sample_trace/` contains trace files for the samples targeted by the stand-alone tools in `recovery_tools/`.
- The full raw-trace and memory-snapshot corpus is not included because it exceeds the storage capacity of the anonymous artifact repository.

Ransomware binaries are not redistributed. They must be obtained separately from the RanDS corpus using the SHA-256 hashes in `samples.csv`.

The repository also provides the VM-side collection and host-side analysis code, pinned rule catalogs with provenance documentation, and the stand-alone recovery tools developed in this study.
