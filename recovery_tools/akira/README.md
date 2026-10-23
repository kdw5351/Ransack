# Akira — ChaCha8 recovery from captured session material

> **Analyzed sample** · SHA-256 `d07b379369e9faea0fed406b9b37652b2fc6453044ab17c1e2189cf61640ab90` · x64 · ~1 MB · first seen on VT 2024.
> Binary not redistributed — see [analyzed samples](../README.md#analyzed-samples).

## Recovery summary

| RANSACK Reported | Recovery-enabling evidence | Analyst-supplied parameters | Matched RCs | Validated |
|---|---|---|---|---|
| `ARX` *h* | 32-byte key and 8-byte nonce at the wrapping sink | ChaCha8†; round count†; byte ranges | RC-07 | **37/38** byte-exact ([run log](validation/VALIDATION.log)) |

RANSACK reported an uncorroborated ARX structural match and RC-07, and captured a 32-byte key plus an 8-byte nonce at the wrapping sink.
The analyst used reference-assisted comparison to identify ChaCha8 and eight rounds, then established the footer fields and byte ranges.

Sources: [report](analysis_report/report.md) · [flow](analysis_report/flow_report.md) · [unified report](analysis_report/unified_report.md) · [source view](analysis_report/sample_view.json) · [recovery details](#recovery-details) · [validation run log](validation/VALIDATION.log)

## Usage

```bash
# print the ChaCha8 key/nonce the run captured
python akira_recover.py recover-key <proc_dir>

# recover every *.akira file in a folder
python akira_recover.py decrypt <proc_dir> <enc_dir> <out_dir>

# optional: verify against held-out originals
python akira_recover.py decrypt <proc_dir> <enc_dir> <out_dir> --known-size <originals>

# no key captured in the run? fall back to key-free salvage of the cleartext regions
python akira_salvage.py recover --in <enc_dir> --out <out_dir>
```

Python 3.10+ (standard library only) — no internet, no payment.

---

## Recovery details

### RANSACK observations

RANSACK reported `encrypted_complete`, an uncorroborated ARX structural match, and RC-07.
The ordinary symmetric-key inventory was empty, but the wrapping sink captured a 32-byte key and an 8-byte nonce.
ChaCha8 and eight rounds were selected with reference assistance; they were not direct pipeline cipher labels.

### Recovered scheme

The 40-byte capture is a ChaCha8 key and nonce.
Each `.akira` file has a 534-byte footer containing a 512-byte wrapped-key block and 22 bytes of metadata:

- metadata byte 12 is the mode: `0` encrypts the whole body, `1` the first half, and `2` four separated chunks;
- bytes 14–17 store the original size as a little-endian integer.

The captured material matches the original Bernstein ChaCha layout at 8 rounds, with a 64-bit counter, 8-byte nonce, and counter starting at 0.

### Recovery method

`akira_recover.py` reads the key/nonce snapshot, parses the footer, decrypts only the spans selected by the mode, and trims to the stored size.
If no wrap input was captured, `akira_salvage.py` remains a key-free fallback for copying regions left in plaintext.

### Result and limits

The result is **37/38 byte-exact**: all mode-0 and mode-1 files passed.
The only mode-2 sample did not provide enough independent evidence to validate its chunk layout, so the tool marks that output as unverified.
Session material is run-specific; without it, whole-file decryption is unavailable.

---

## Validation

[`validation/VALIDATION.log`](validation/VALIDATION.log) records the full-run validation result summarized above: the family's actual encrypted files, decrypted with the key material that run captured.

The repository additionally ships a small, benign synthetic subset.
It checks that the finished recovery tool still handles the represented path; it does not reproduce trace capture or replace the result above.

| Validation scope | Input | Recorded result |
|---|---|---|
| Captured run | the family's encrypted files, with the key material that run captured | `37/38` byte-exact |
| Partial synthetic regression subset | `4` benign originals, `4` Akira-format inputs, and `1` synthetic key/nonce capture (modes 0 and 1) | run `validation/run_validation.py` to produce it |

Run from this family directory.
Note that it rewrites `VALIDATION.log` with its own synthetic-subset result, so keep a copy first if the committed run matters to you:

```bash
python validation/run_validation.py
```

## Analysis reports

- **family**: `akira`
- **execution_quality**: `encrypted_complete`
- **recovery tier**: `RC_MATCHED` (1/7 RC cases passed)
- **pipeline flags**: NO_PAYLOAD_RUN=`False` · VALIDATED=`False`
- **loop-classifier `primary_cipher`**: `XOR (rotate) (heuristic, unconfirmed)` (confidence 0.35)
- **pipeline metrics**: Key Detection=`yes` · File Recoverability=`yes` · Loop-Based Behavior Recovery=`yes`

### Report files

| file | what it contains |
|---|---|
| [flow_report.md](analysis_report/flow_report.md) | 10-stage key/cipher/loop flow (Stage 1 identity → Stage 10 Mermaid diagram). |
| [report.md](analysis_report/report.md) | Per-sample verdict, RC-01..07 checklist, and recovery-synthesis evidence (cipher / round count / I/O chunk size). |
| [unified_report.md](analysis_report/unified_report.md) | Consolidated single-page view: identity, recovery verdict, API trace, file ops, loop categories, top-10 scored loops. |
| [sample_view.json](analysis_report/sample_view.json) | Raw flattened view emitted by the report generator — every value rendered into the three reports lives here. |
