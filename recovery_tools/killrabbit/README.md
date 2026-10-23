# KillRabbit — AES-256-CBC recovery from a captured run key

> **Analyzed sample** · SHA-256 `d4eb98701bc0c33b5f9c3e202bf55c1b2e2cb1c1e4b7c81ad6305d7938d0f959` · x86 · ~1 MB · first seen on VT 2018.
> Binary not redistributed — see [analyzed samples](../README.md#analyzed-samples).

## Recovery summary

| RANSACK Reported | Recovery-enabling evidence | Analyst-supplied parameters | Matched RCs | Validated |
|---|---|---|---|---|
| `AES-256-CBC` | 32-byte key from a residue snapshot | IV = 0 | RC-04, RC-06, RC-07 | **40/40** byte-exact ([run log](validation/VALIDATION.log)) |

RANSACK reported AES-256-CBC, recovered a 32-byte key from a residue snapshot, and fired RC-04, RC-06, and RC-07.
The analyst established the zero IV and confirmed the run-wide key-to-file binding.

Sources: [report](analysis_report/report.md) · [flow](analysis_report/flow_report.md) · [unified report](analysis_report/unified_report.md) · [source view](analysis_report/sample_view.json) · [recovery details](#recovery-details) · [validation run log](validation/VALIDATION.log)

## Usage

```
python killrabbit_recover.py recover-key --in <enc_dir> --trace <proc_dir>
python killrabbit_recover.py decrypt     --in <enc_dir> --trace <proc_dir> --out <dir> [--ext .killrabbit]
#   or supply the key directly:  --key <64-hex>
```

`--trace` a KillRabbit trace process dir with the key-residue `crypto_*.bin`.
Python 3.10+ with `pycryptodome`.
No internet, no payment.

---

## Recovery details

### RANSACK observations

RANSACK reported `encrypted_complete` and RC-04, RC-06, and RC-07.
It recorded one 32-byte AES-256 candidate at `crypto_10.bin`, 247 tagged sinks, and AES key-schedule evidence.
RC-04's high hardcoded-key ratio is chain attribution for a reused run key; it does not prove that the key is embedded in the binary.

### Recovered scheme

KillRabbit uses one random AES-256 key for the run.
Files are encrypted in full with AES-256-CBC, IV = 0, and PKCS#7 padding, then renamed with `.killrabbit`.
There is no RSA-wrapped per-file key or additional footer.

### Recovery method

`killrabbit_recover.py recover-key` tests captured 32-byte candidates against the first blocks of several files.
The correct candidate produces known file signatures or structured text across the corpus.
`decrypt` applies that key to every file from the same run and removes PKCS#7 padding.

### Result and limits

The recovered run key produced **40/40 byte-exact** files.
A different infection requires its own captured key; this is not a build-wide key and does not apply when the relevant key buffer was not captured.

---

## Validation

[`validation/VALIDATION.log`](validation/VALIDATION.log) records the full-run validation result summarized above: the family's actual encrypted files, decrypted with the key material that run captured.

The repository additionally ships a small, benign synthetic subset.
It checks that the finished recovery tool still handles the represented path; it does not reproduce trace capture or replace the result above.

| Validation scope | Input | Recorded result |
|---|---|---|
| Captured run | the family's encrypted files, with the key material that run captured | `40/40` byte-exact |
| Partial synthetic regression subset | `4` benign originals, `4` KillRabbit-format inputs, and `1` synthetic key capture | run `validation/run_validation.py` to produce it |

Run from this family directory.
Note that it rewrites `VALIDATION.log` with its own synthetic-subset result, so keep a copy first if the committed run matters to you:

```bash
python validation/run_validation.py
```

## Analysis reports

- **family**: `killrabbit`
- **execution_quality**: `encrypted_complete`
- **recovery tier**: `RC_MATCHED` (3/7 RC cases passed)
- **pipeline flags**: NO_PAYLOAD_RUN=`False` · VALIDATED=`False`
- **loop-classifier `primary_cipher`**: `AES-256-CBC` (confidence 0.9)
- **pipeline metrics**: Key Detection=`yes` · File Recoverability=`yes` · Loop-Based Behavior Recovery=`yes`

### Report files

| file | what it contains |
|---|---|
| [flow_report.md](analysis_report/flow_report.md) | 10-stage key/cipher/loop flow (Stage 1 identity → Stage 10 Mermaid diagram). |
| [report.md](analysis_report/report.md) | Per-sample verdict, RC-01..07 checklist, and recovery-synthesis evidence (cipher / round count / I/O chunk size). |
| [unified_report.md](analysis_report/unified_report.md) | Consolidated single-page view: identity, recovery verdict, API trace, file ops, loop categories, top-10 scored loops. |
| [sample_view.json](analysis_report/sample_view.json) | Raw flattened view emitted by the report generator — every value rendered into the three reports lives here. |
