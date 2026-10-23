# Makop — Key-free plaintext-residue recovery

> **Analyzed sample** · SHA-256 `d0dd0f7658b938f9a3036ce308f5018ae0cf3bc516aaf3c18b947afee136c043` · x86 · ~42 KB · first seen on VT 2022.
> Binary not redistributed — see [analyzed samples](../README.md#analyzed-samples).

## Recovery summary

| RANSACK Reported | Recovery-enabling evidence | Analyst-supplied parameters | Matched RCs | Validated |
|---|---|---|---|---|
| `AES-256` *i* | Provider-boundary sink plaintext★ | File-type signature; end-marker or NUL trim | RC-05, RC-06, RC-07 | **9/10** structurally recovered *s* ([run log](validation/VALIDATION.log)) |

RANSACK reported AES-256 by key-length inference and fired RC-05, RC-06, and RC-07, but it did not capture a usable victim-file key.
The analyst reconstructed the provider-boundary plaintext with file-type signatures, format end markers, or NUL trimming.
The working construction used a re-capture configured to retain full plaintext inputs at the encryption sink.

Sources: [report](analysis_report/report.md) · [flow](analysis_report/flow_report.md) · [unified report](analysis_report/unified_report.md) · [source view](analysis_report/sample_view.json) · [recovery details](#recovery-details) · [validation run log](validation/VALIDATION.log)

## Usage

```
python makop_recover.py extract <proc_dir> [out_dir]
```

- `<proc_dir>` — a Makop trace process directory containing `plain_*.bin`.
- `[out_dir]` — output directory (default `recovered/`).

The tool identifies each residue by file signature, trims the over-captured tail (containers — ZIP/PNG/JPEG/PDF — are trimmed exactly via their end markers; text/markup is trimmed at the first `0x00` byte, which is byte-exact because the text contains no NUL), de-duplicates, and writes `recovered_NNN.<ext>`.

Diagnostic (shows the captured key is a config key, not a file key):

```
python makop_recover.py keyprobe <proc_dir> [encrypted.mkp]
```

---

## Recovery details

### RANSACK observations

RANSACK reported `encrypted_complete`, AES-256 by inference from an observed 32-byte candidate, and RC-05, RC-06, and RC-07.
Testing shows that candidate is the static configuration-decryption key, not a victim-file key.

### File-key boundary

Makop uses a random AES key per file and seals it with the operator's RSA public key in the `.mkp` footer.
The supporting trace contains no usable RSA private key.
`makop_recover.py keyprobe` confirms that the captured configuration key does not decrypt `.mkp` bodies, so the RC matches do not provide a key-based file decryptor.

The observed layout is AES-CBC-compatible ciphertext followed by roughly 212–228 bytes of wrapped-key metadata ending in a constant marker.
Mode and exact footer details are not needed by the residue path.

### Recovery method

The encrypt sink receives plaintext before the buffer is overwritten.
A capture configured for full sink input writes those buffers as `plain_*.bin`.
`makop_recover.py extract` de-duplicates them, identifies the file type, and determines the end boundary from the captured data:

- ZIP, PNG, JPEG, and PDF use their format end markers;
- text and markup stop at the first NUL;
- GIF trimming is heuristic and was not exercised by the verified corpus.

The tool reconstructs only content present in captured sink inputs; it does not decrypt existing `.mkp` files without such residue.

### Result and limits

Nine of ten files were recovered **byte-exact**.
The remaining raw binary payload was present in the snapshot, but it had no signature, end marker, or NUL from which to determine its exact length.
Recovery is limited to the instrumented run and configured capture window.
It recovers file content, not the RSA-sealed file keys.

---

## Validation

[`validation/VALIDATION.log`](validation/VALIDATION.log) records the full-run validation result summarized above: the family's actual encrypted files, decrypted with the key material that run captured.

The repository additionally ships a small, benign synthetic subset.
It checks that the finished recovery tool still handles the represented path; it does not reproduce trace capture or replace the result above.

| Validation scope | Input | Recorded result |
|---|---|---|
| Captured run | the family's plaintext-residue snapshots, trimmed by the data itself | `9/10` structurally recovered |
| Partial synthetic regression subset | `4` benign originals and `4` synthetic plaintext-residue snapshots | run `validation/run_validation.py` to produce it |

Run from this family directory.
Note that it rewrites `VALIDATION.log` with its own synthetic-subset result, so keep a copy first if the committed run matters to you:

```bash
python validation/run_validation.py
```

## Analysis reports

- **family**: `makop`
- **execution_quality**: `encrypted_complete`
- **recovery tier**: `RC_MATCHED` (3/7 RC cases passed)
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
