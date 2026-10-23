# Chaos — Per-file AES recovery from captured key/IV values

> **Analyzed sample** · SHA-256 `a2a703b827fcb58f31e93168b5224543ed9179887cb3f642fdd57e5260ee84d9` · x86 (I386) · ~2 MB · packing unknown · first seen on VT 2025 · trace `proc_2360`.
> Binary not redistributed — see [analyzed samples](../README.md#analyzed-samples).

## Recovery summary

| RANSACK Reported | Recovery-enabling evidence | Analyst-supplied parameters | Matched RCs | Validated |
|---|---|---|---|---|
| `none` | Per-file `KEY\|IV` at the RSA wrapping sink | AES-256; CBC | RC-07 | **510/514** byte-exact ([run log](validation/VALIDATION.log)) |

RANSACK identified no cipher, but fired RC-07 after observing per-file `KEY|IV` material at the RSA wrapping sink.
The analyst established the 32-byte key/16-byte IV split, AES-256-CBC, the binding between each captured value and its file, and the intermittent large-file layout.

Sources: [report](analysis_report/report.md) · [flow](analysis_report/flow_report.md) · [unified report](analysis_report/unified_report.md) · [source view](analysis_report/sample_view.json) · [recovery details](#recovery-details) · [validation run log](validation/VALIDATION.log)

## Usage

```bash
# list the per-file key|iv captured in the trace
python chaos_recover.py list-keys --trace <proc_dir>

# decrypt every encrypted file (key auto-recovered per file from the trace)
python chaos_recover.py decrypt --in locked/ --trace <proc_dir> --out recovered/

# --known-size verifies byte-exact against held originals (same base name)
python chaos_recover.py decrypt --in locked/ --trace <proc_dir> --out recovered/ --known-size originals/
```
Requires Python 3.10+ and `pycryptodome`.

---

## Recovery details

### RANSACK observations

RANSACK reported no cipher and matched RC-07 from per-file `KEY|IV` values observed at the RSA wrapping sink.
The ordinary inventory still reports `Total sym_keys=0`, while the matched primitive records 8,192 plaintext wrap-input captures.
The analyst inspected those captures, confirmed the 32-byte key and 16-byte IV split, identified AES-256-CBC, and established their file binding.

### Recovered scheme

Chaos generates a new 32-character key and 16-character IV for each file.
Their ASCII bytes are used directly for AES-256-CBC and the combined 49-byte value is RSA-2048-wrapped into a 256-byte trailer.

- Small files are encrypted in full with PKCS#7 padding.
- Large files use three 128 KiB encrypted chunks at the head, middle, and tail; the gaps remain plaintext.

### Recovery method

`chaos_recover.py` harvests captured `KEY|IV` values, removes the RSA trailer, and matches a capture to a file by decrypting the first block and checking its structure.
It then applies full-file or intermittent decryption according to file size.
Key selection chooses among captured values; it does not guess or brute-force key bytes.

### Result and limits

The analyzed run recovered **510/514 byte-exact**.
One file was never encrypted.
Three large files were partially recovered because their later chunk keys fell outside that capture window.
Keys are random and per-file, so recovery requires the corresponding run's wrap-input captures.

---

## Validation

[`validation/VALIDATION.log`](validation/VALIDATION.log) records the full-run validation result summarized above: the family's actual encrypted files, decrypted with the key material that run captured.

The repository additionally ships a small, benign synthetic subset.
It checks that the finished recovery tool still handles the represented path; it does not reproduce trace capture or replace the result above.

| Validation scope | Input | Recorded result |
|---|---|---|
| Captured run | the family's encrypted files, with the key material that run captured | `510/514` byte-exact |
| Partial synthetic regression subset | `4` benign originals, `4` Chaos-format inputs, and `1` synthetic capture containing four per-file key/IV values | run `validation/run_validation.py` to produce it |

Run from this family directory.
Note that it rewrites `VALIDATION.log` with its own synthetic-subset result, so keep a copy first if the committed run matters to you:

```bash
python validation/run_validation.py
```

## Analysis reports

- **family**: `chaos`
- **execution_quality**: `encrypted_complete`
- **recovery tier**: `RC_MATCHED` (1/7 RC cases passed)
- **pipeline flags**: NO_PAYLOAD_RUN=`False` · VALIDATED=`False`
- **loop-classifier `primary_cipher`**: `no cipher identified` (confidence 0.0)
- **pipeline metrics**: Key Detection=`yes` · File Recoverability=`yes` · Loop-Based Behavior Recovery=`no`

### Report files

| file | what it contains |
|---|---|
| [flow_report.md](analysis_report/flow_report.md) | 10-stage key/cipher/loop flow (Stage 1 identity → Stage 10 Mermaid diagram). |
| [report.md](analysis_report/report.md) | Per-sample verdict, RC-01..07 checklist, and recovery-synthesis evidence (cipher / round count / I/O chunk size). |
| [unified_report.md](analysis_report/unified_report.md) | Consolidated single-page view: identity, recovery verdict, API trace, file ops, loop categories, top-10 scored loops. |
| [sample_view.json](analysis_report/sample_view.json) | Raw flattened view emitted by the report generator — every value rendered into the three reports lives here. |
