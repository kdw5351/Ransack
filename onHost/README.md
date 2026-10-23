# Host-side analysis

`onHost/` analyses one PIN trace and produces an auditable, per-sample recovery-evidence report.
Use the root [How To Use](../README.md#how-to-use) for dependency installation and the end-to-end capture-to-analysis workflow.

## Input and output

The input is the top-level `trace_<sample>\` directory that contains one or more `proc_<pid>\` directories.
`main.py` writes intermediate analysis data under `<trace>/_analysis/`.
`report/generate.py` writes the final report bundle under `<trace>/_paper_report/`.
Quiet-mode stage failures are preserved as `<trace>/_analysis/_stage1.log` or `_stage2.log`.

## Entry points

| Path | Role |
|---|---|
| `run.py` | Recommended driver for analysis followed by report generation. |
| `main.py` | Stage-one analyser used internally by `run.py`. |
| `analysis/` | Trace loading, loop classification, key-flow analysis, residue scanning, and RC evaluation. |
| `report/` | View construction and Markdown/JSON report generation. |

## `run.py` options

| Argument | Behaviour |
|---|---|
| `<trace_dir>` | Analyse one trace directory. |
| `--all <root>` | Analyse every `trace_*` child under a directory. |
| `--skip-done` | Skip traces that already contain all five final report files. |
| `--out-mirror <dir>` | Mirror generated reports to another directory. |
| `--quiet` | Suppress normal stage output while preserving failure logs. |

## Pipeline

`trace_<sample>/` -> `main.py` -> `_analysis/` -> `report/generate.py` -> `_paper_report/`.
The analyser loads `loop_patterns.json`, `dll_roles.json`, `crypto_constants.json`, and `sym_key_inference_rules.json` from `assets\`.