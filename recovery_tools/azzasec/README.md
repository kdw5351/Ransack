# AzzaSec — Password-derived AES-256-CBC recovery

> **Analyzed sample** · SHA-256 `58b45bfd8430d8b24f9142278ff206261ab3d1100b3c98b0fdfcefdddf2fd05d` · x86 (I386) · ~1 MB (1,474,048 B) · packed (entropy 7.07) · first seen on VT 2024 · trace `proc_6940`.
> Binary not redistributed — see [analyzed samples](../README.md#analyzed-samples).

## Recovery summary

| RANSACK Reported | Recovery-enabling evidence | Analyst-supplied parameters | Matched RCs | Validated |
|---|---|---|---|---|
| `none` | 20-character password from a separate trace‡ | SHA-512-derived AES-256-CBC; PKCS#7 | — | **30/30** byte-exact ([run log](validation/VALIDATION.log)) |

RANSACK reported no cipher or RC match because the bundled run failed to attach and captured no usable execution evidence.
A separate trace supplied the 20-character password, and the analyst established the SHA-512-derived AES-256-CBC construction and PKCS#7 padding.

Sources: [report](analysis_report/report.md) · [flow](analysis_report/flow_report.md) · [unified report](analysis_report/unified_report.md) · [source view](analysis_report/sample_view.json) · [recovery details](#recovery-details) · [validation run log](validation/VALIDATION.log)

## Usage

```bash
# recover just the password + key/IV from the trace
python azzasec_recover.py recover-key --in locked/ --trace <proc_dir>

# decrypt every *.AzzaSec (password auto-recovered from the trace)
python azzasec_recover.py decrypt --in locked/ --trace <proc_dir> --out recovered/

# or pass the password (or key+IV) directly; --known-size verifies byte-exact against originals
python azzasec_recover.py decrypt --in locked/ --password <str> --out recovered/
python azzasec_recover.py decrypt --in locked/ --key <hex> --iv <hex> --out recovered/ --known-size originals/
```
Requires Python 3.10+ and `pycryptodome`.

---

## Recovery details

### Evidence boundary

RANSACK reported `pin_attach_failed` / `NO_PAYLOAD_RUN`, no cipher, and no RC match for the bundled run.
That run captured no crypto, key, sink, or file I/O evidence and does not support the recovery result.
A separate trace, `proc_6940`, supplied the 20-character password used by the recovery tool.

### Recovered scheme

The supporting trace contains a 20-character run password.
AzzaSec computes SHA-512 once, uses digest bytes 0–31 as the AES-256 key and bytes 32–47 as the IV, then encrypts each complete file with AES-256-CBC and PKCS#7.
The same key and IV are reused across the run, and `.AzzaSec` files contain only ciphertext—no key-bearing header or footer.

### Recovery method

`azzasec_recover.py` tests short ASCII trace buffers as password candidates.
A valid candidate must give valid PKCS#7 across the files and restore multiple known file signatures.
The tool then derives the key and IV with SHA-512 and decrypts every file.
A password, or explicit key and IV, may also be supplied.

### Result and limits

The separate recovery trace produced **30/30 byte-exact**, including the encrypted sample binary.
The password is random and run-specific; files cannot be recovered from the bundled failed-attach run or from encrypted files alone.

---

## Validation

[`validation/VALIDATION.log`](validation/VALIDATION.log) records the full-run validation result summarized above: the family's actual encrypted files, decrypted with the key material that run captured.

The repository additionally ships a small, benign synthetic subset.
It checks that the finished recovery tool still handles the represented path; it does not reproduce trace capture or replace the result above.

| Validation scope | Input | Recorded result |
|---|---|---|
| Captured run | the family's encrypted files, with the key material that run captured | `30/30` byte-exact |
| Partial synthetic regression subset | `4` benign originals, `4` AzzaSec-format inputs, and `1` synthetic password capture | run `validation/run_validation.py` to produce it |

Run from this family directory.
Note that it rewrites `VALIDATION.log` with its own synthetic-subset result, so keep a copy first if the committed run matters to you:

```bash
python validation/run_validation.py
```

## Analysis reports

- **family**: `azzasec`
- **execution_quality**: `pin_attach_failed`
- **recovery tier**: `NO_PAYLOAD_RUN` (0/7 RC cases passed)
- **pipeline flags**: NO_PAYLOAD_RUN=`True` · VALIDATED=`False`
- **loop-classifier `primary_cipher`**: `no cipher identified` (confidence 0.0)
- **pipeline metrics**: Key Detection=`no` · File Recoverability=`no` · Loop-Based Behavior Recovery=`no`

### Report files

| file | what it contains |
|---|---|
| [flow_report.md](analysis_report/flow_report.md) | 10-stage key/cipher/loop flow (Stage 1 identity → Stage 10 Mermaid diagram). |
| [report.md](analysis_report/report.md) | Per-sample verdict, RC-01..07 checklist, and recovery-synthesis evidence (cipher / round count / I/O chunk size). |
| [unified_report.md](analysis_report/unified_report.md) | Consolidated single-page view: identity, recovery verdict, API trace, file ops, loop categories, top-10 scored loops. |
| [sample_view.json](analysis_report/sample_view.json) | Raw flattened view emitted by the report generator — every value rendered into the three reports lives here. |
