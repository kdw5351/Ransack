# HDLocker — Build-scoped TEA recovery

> **Analyzed sample** · SHA-256 `b74d0a068b387f7569f9a42729853e742a99ccd71c45946ae153a39eba6b153e` · x86 · ~776 KB · first seen on VT 2021.
> Binary not redistributed — see [analyzed samples](../README.md#analyzed-samples).

## Recovery summary

| RANSACK Reported | Recovery-enabling evidence | Analyst-supplied parameters | Matched RCs | Validated |
|---|---|---|---|---|
| `TEA-16` | Analyst-extracted 73,728-byte `.data` keyspace | Custom CBC; IV = 0 | RC-06 | **74/74** byte-exact ([run log](validation/VALIDATION.log)) |

RANSACK reported 16-round TEA and RC-06 from the `tea_delta` artifact, but it did not recover the key.
The analyst extracted the 73,728-byte `.data` keyspace and established the custom CBC-like chaining and zero IV.

Sources: [report](analysis_report/report.md) · [flow](analysis_report/flow_report.md) · [unified report](analysis_report/unified_report.md) · [source view](analysis_report/sample_view.json) · [recovery details](#recovery-details) · [validation run log](validation/VALIDATION.log)

## Usage

```bash
# batch decrypt a locked folder
python hdlocker_decrypt.py --in-dir locked/ --out-dir recovered/

# interactive (prompts for the folders)
python hdlocker_decrypt.py

# optional: force exact prefix from original sizes (validation cross-check)
python hdlocker_decrypt.py --in-dir locked/ --out-dir recovered/ --known-size originals/
```

Requires Python 3.10+ only — no third-party libraries.

---

## Recovery details

### RANSACK observations

RANSACK reported `encrypted_partial` and RC-06 from the TEA delta constant for the bundled run.
It recorded 324 hot loops but no RNG calls, crypto sinks, captured symmetric keys, or key residue.
RANSACK identified the cipher family but did not supply a file key.

### Recovered scheme

| Property | Value |
|---|---|
| Cipher | 16-round TEA, big-endian 64-bit blocks |
| Chaining | Custom CBC-like construction, IV = 0 |
| File marker | `HDLocker_` |
| Key source | One 16-byte window in the bundled 73,728-byte `.data` keyspace |

The selected key varies between executions; observed offsets include `0x810`, `0x5c71`, and `0x7940`.
The keyspace is build-scoped, so `hdlocker_keyspace.bin` must match the ransomware build.
The value in the dropped `HD_*.log` note is not the file key.

### Recovery method and file layout

`hdlocker_decrypt.py` tests the 73,713 possible 16-byte windows and keeps the candidate that produces recognizable plaintext.

- Small bodies (at most 50,016 bytes) contain a 3–10 byte prefix, the file content, and a 7-byte tail.
  The tool resolves the prefix from file structure and cross-file alignment; `--known-size` can provide an exact boundary for validation.
- Large bodies contain a plaintext tail plus a 50,016-byte encrypted region.
  Decryption yields a 9-byte prefix and the first 50,000 bytes of the original.

### Result and limits

The validated corpus recovered **74/74 byte-exact**.
Recovery is offline but build-specific.
A lone high-entropy small file with no recognizable header or related peer may need `--known-size`; the tool flags an unresolved boundary instead of guessing it.

---

## Validation

[`validation/VALIDATION.log`](validation/VALIDATION.log) records the full-run validation result summarized above: the family's actual encrypted files, decrypted with the key material that run captured.

The repository additionally ships a small, benign synthetic subset.
It checks that the finished recovery tool still handles the represented path; it does not reproduce trace capture or replace the result above.

| Validation scope | Input | Recorded result |
|---|---|---|
| Captured run | the family's encrypted files, with the key material that run captured | `74/74` byte-exact |
| Partial synthetic regression subset | `4` benign originals and `4` HDLocker-format encrypted inputs | run `validation/run_validation.py` to produce it |

Run from this family directory.
Note that it rewrites `VALIDATION.log` with its own synthetic-subset result, so keep a copy first if the committed run matters to you:

```bash
python validation/run_validation.py
```

## Analysis reports

- **family**: `hdlocker`
- **execution_quality**: `encrypted_partial`
- **recovery tier**: `RC_MATCHED` (1/7 RC cases passed)
- **pipeline flags**: NO_PAYLOAD_RUN=`False` · VALIDATED=`False`
- **loop-classifier `primary_cipher`**: `TEA (16-round; decisive constant tea_delta)` (confidence 0.9)
- **pipeline metrics**: Key Detection=`no` · File Recoverability=`yes` · Loop-Based Behavior Recovery=`yes`

### Report files

| file | what it contains |
|---|---|
| [flow_report.md](analysis_report/flow_report.md) | 10-stage key/cipher/loop flow (Stage 1 identity → Stage 10 Mermaid diagram). |
| [report.md](analysis_report/report.md) | Per-sample verdict, RC-01..07 checklist, and recovery-synthesis evidence (cipher / round count / I/O chunk size). |
| [unified_report.md](analysis_report/unified_report.md) | Consolidated single-page view: identity, recovery verdict, API trace, file ops, loop categories, top-10 scored loops. |
| [sample_view.json](analysis_report/sample_view.json) | Raw flattened view emitted by the report generator — every value rendered into the three reports lives here. |
