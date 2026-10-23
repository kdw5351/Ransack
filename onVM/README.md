# VM-side capture

`onVM/` contains the Intel PIN launcher and Pintool source used to capture recovery-relevant runtime evidence inside the Windows VM.
Use the root [How To Use](../README.md#how-to-use) for build, VM deployment, and end-to-end execution steps.

## Runtime contract

`run.ps1` expects the complete PIN kit at `..\pin\`, rule catalogues at `..\assets\`, and both Pintool DLLs under `ransomflow\Build\`.
The VM capture tool requires `crypto_api.json`, `io_activity.json`, and `dll_roles.json` from `assets\`.
`run.ps1` detects the sample architecture, selects the matching Pintool, and retries with the other architecture when needed.
The Pintool follows child processes, records cryptographic and file-I/O API activity, captures hot loops, and snapshots key-birth memory regions.
Each run writes `traces\trace_<sample>\` with one `proc_<pid>\` directory per followed process.
A capture is complete when `ransomflow_done.json` appears in the trace.
Running the same sample filename again replaces its previous trace directory.
Pass the top-level `trace_<sample>\` directory, not an individual `proc_<pid>\`, to the host analyser.

## Trace contents

| Artifact | Purpose |
|---|---|
| `proc_info.json`, `images_*.jsonl` | Process identity and loaded images. |
| `io_events_*.jsonl`, `crypto_events_*.jsonl` | File-I/O and cryptographic API events. |
| `loop_*.{json,bin}`, `loop_events.jsonl` | Captured hot-loop metadata, bytes, and final counts. |
| `key_residue_snapshots_*.jsonl`, `crypto_*.bin` | Key-birth snapshot index and memory regions. |
| `ransomflow_done.json` | Completion marker and runtime statistics. |

A compact captured trace is included at [`onHost/example_trace/`](../onHost/example_trace/).
Its `proc_4321/` directory demonstrates the host analyser's input layout, while `expected/` contains the reference reports generated from that trace.
