# NitroRansomware — Build-scoped password recovery

> **Analyzed sample** · SHA-256 `d035e86bc527b1bbe1aecee656db2263a0fc130c34a402ef501740c6ad257f7f` · x86 (.NET, I386) · ~60 KB · first seen on VT 2021.
> Binary not redistributed — see [analyzed samples](../README.md#analyzed-samples).

## Recovery summary

| RANSACK Reported | Recovery-enabling evidence | Analyst-supplied parameters | Matched RCs | Validated |
|---|---|---|---|---|
| `none` | Fixed password from HMAC-pad artifacts | AES-256-CBC; PBKDF2-SHA1, 50k | — | **28/28** byte-exact ([run log](validation/VALIDATION.log)) |

RANSACK reported no cipher or RC match because the bundled native trace did not expose the managed encryption boundary.
Post-report analysis recovered the fixed password from HMAC-pad artifacts and established AES-256-CBC with PBKDF2-HMAC-SHA1 at 50,000 iterations.

Sources: [report](analysis_report/report.md) · [flow](analysis_report/flow_report.md) · [unified report](analysis_report/unified_report.md) · [source view](analysis_report/sample_view.json) · [recovery details](#recovery-details) · [validation run log](validation/VALIDATION.log)

## Usage

```bash
python nitro_recover.py recover-key                       # print the build-fixed password
python nitro_recover.py recover-key --trace <trace_dir>   # fold it back from the captured HMAC pads
python nitro_recover.py decrypt --in <enc_dir> --out <out_dir>
# byte-exact check against a directory of the original files:
python nitro_recover.py decrypt --in <enc_dir> --out <out_dir> --known-size <originals_dir>
# a hypothetical build with a different embedded password:
python nitro_recover.py decrypt --in <enc_dir> --out <out_dir> --password <ascii>
```
Requires Python 3.10+ with `pycryptodome`.

---

## Recovery details

### Evidence boundary

RANSACK reported `encrypted_partial` / `INFEASIBLE`, no cipher, and no RC match for the bundled run.
The native trace did not expose the managed .NET encryption boundary or a captured final key.
Post-report managed-code analysis and HMAC-pad artifacts supplied the fixed password and KDF path.

### Recovered scheme

Each `.givemenitro` file is `[32-byte salt][AES ciphertext]`.
The build password feeds PBKDF2-HMAC-SHA1 with 50,000 iterations; the first 32 derived bytes are the AES-256 key and the next 16 are the IV.
The body uses AES-256-CBC with PKCS#7 padding.

For the analyzed build, HMAC ipad/opad artifacts fold back to the 20-byte value `ZGVmYXVsdHBhc3N3b3Jk`, which is base64 for `defaultpassword`.
The password is a build setting, not a per-victim secret.

### Recovery method

`nitro_recover.py recover-key --trace` can recover the password from matching HMAC pad artifacts.
`decrypt` reads the clear salt, derives 48 bytes with PBKDF2-HMAC-SHA1, decrypts the body, and removes PKCS#7 padding.
`--password` supports a build that embeds a different password.

### Result and limits

The analyzed default-password build recovered **28/28 byte-exact**; an empty encrypted copy of the ransomware executable is skipped.
Recovery is build-scoped.
A custom build requires its configured password or matching supporting artifacts, and the bundled native-analysis result alone is insufficient.

---

## Validation

[`validation/VALIDATION.log`](validation/VALIDATION.log) records the full-run validation result summarized above: the family's actual encrypted files, decrypted with the key material that run captured.

The repository additionally ships a small, benign synthetic subset.
It checks that the finished recovery tool still handles the represented path; it does not reproduce trace capture or replace the result above.

| Validation scope | Input | Recorded result |
|---|---|---|
| Captured run | the family's encrypted files, with the key material that run captured | `28/28` byte-exact |
| Partial synthetic regression subset | `3` benign originals and `3` Nitro-format encrypted inputs | run `validation/run_validation.py` to produce it |

Run from this family directory.
Note that it rewrites `VALIDATION.log` with its own synthetic-subset result, so keep a copy first if the committed run matters to you:

```bash
python validation/run_validation.py
```

## Analysis reports

- **family**: `nitro`
- **execution_quality**: `encrypted_partial`
- **recovery tier**: `INFEASIBLE` (0/7 RC cases passed)
- **pipeline flags**: NO_PAYLOAD_RUN=`False` · VALIDATED=`False`
- **loop-classifier `primary_cipher`**: `no cipher identified` (confidence 0.0)
- **pipeline metrics**: Key Detection=`yes` · File Recoverability=`no` · Loop-Based Behavior Recovery=`no`

### Report files

| file | what it contains |
|---|---|
| [flow_report.md](analysis_report/flow_report.md) | 10-stage key/cipher/loop flow (Stage 1 identity → Stage 10 Mermaid diagram). |
| [report.md](analysis_report/report.md) | Per-sample verdict, RC-01..07 checklist, and recovery-synthesis evidence (cipher / round count / I/O chunk size). |
| [unified_report.md](analysis_report/unified_report.md) | Consolidated single-page view: identity, recovery verdict, API trace, file ops, loop categories, top-10 scored loops. |
| [sample_view.json](analysis_report/sample_view.json) | Raw flattened view emitted by the report generator — every value rendered into the three reports lives here. |
