# Razrusheniye — AES key recovery with plaintext-residue fallback

> **Analyzed sample** · SHA-256 `c98c470dc1db8a9caba66de0da76fd465685d25e830c30d40cdc422dc9d66bb2` · x64 · ~20 KB · first seen on VT 2024.
> Binary not redistributed — see [analyzed samples](../README.md#analyzed-samples).

## Recovery summary

| RANSACK Reported | Recovery-enabling evidence | Analyst-supplied parameters | Matched RCs | Validated |
|---|---|---|---|---|
| `AES-256` *i* | 32-byte key and IV from a residue snapshot | CBC | RC-04, RC-05, RC-06, RC-07 | **552/558** byte-exact ([run log](validation/VALIDATION.log)) |

RANSACK reported AES-256 by key-length inference from a 32-byte key/IV residue snapshot and fired RC-04, RC-05, RC-06, and RC-07.
The analyst established CBC mode, verified the run-wide key/IV binding, and handled files whose ciphertext represents only part of the original.

Sources: [report](analysis_report/report.md) · [flow](analysis_report/flow_report.md) · [unified report](analysis_report/unified_report.md) · [source view](analysis_report/sample_view.json) · [recovery details](#recovery-details) · [validation run log](validation/VALIDATION.log)

## Usage

```bash
# key + IV from the trace, confirmed against the sealed files
python razrusheniye_keyrecover.py recover-key <proc_dir> --enc <enc_dir>

# decrypt everything
python razrusheniye_keyrecover.py decrypt <proc_dir> <enc_dir> <out_dir>

# optional: verify against held-out originals
python razrusheniye_keyrecover.py decrypt <proc_dir> <enc_dir> <out_dir> --known <orig_dir>
```

Python 3.10+ with `pycryptodome`.
No internet, no payment.

If `recover-key` reports no key, the trace snapshotted no keygen input and no candidate window worked.
Use the key-free path instead:

```
python razrusheniye_recover.py extract <proc_dir> [out_dir]
```

That tool identifies each residue by file signature and trims the over-captured tail (containers by their end markers; GIF by a heuristic `0x00 0x3B` marker, not validated and not exercised by the verified corpus; text and markup at the first NUL, which is byte-exact because text carries none), de-duplicates, and writes `recovered_NNN.<ext>`.
It needs `plain_*.bin`, which only a capture with full plaintext residue enabled produces.

`razrusheniye_recover.py keysearch <proc_dir> <encrypted.raz>` is its diagnostic.
It reports nothing on the earlier trace, and that negative is now known to be wrong: it slices candidates at fixed offsets, reads only the first 96 bytes of each snapshot, checks only CBC block 1, and never hashes, so it cannot reach a derived key.
Prefer `recover-key`.

---

## Recovery details

### RANSACK observations

RANSACK reported AES-256 by inference from observed 32-byte key material and fired RC-04, RC-05, RC-06, and RC-07.
The key and IV residue are accepted only after the recovery tool verifies their binding against the encrypted files.

### Recovered scheme

The supported run uses one AES-256-CBC key and one IV across its `.raz` files.
Where the trace captures the `CryptHashData` or key-generation input, `razrusheniye_keyrecover.py` recomputes candidates as `SHA-256(input[:32])`, tests them against the ciphertext set, and selects an IV that restores multiple known file signatures.
It also searches repeated captured windows when a directly usable candidate is present.

### Recovery paths

- `razrusheniye_keyrecover.py` is the primary path.
  It recovers the run key and IV, decrypts every complete AES block, removes valid padding, and reports files whose ciphertext is shorter than the original.
- `razrusheniye_recover.py extract` is the fallback for traces that contain `plain_*.bin` but not enough derivation material.
  It identifies file types and trims captured plaintext by container end markers or the first NUL for text.
- The older `keysearch` command checks fixed buffer slices and does not reproduce the derivation; it is diagnostic, not the preferred path.

### Result and limits

Key-based recovery produced **552/558 byte-exact** files.
The remaining six contain less ciphertext than the corresponding original and can only be recovered for the represented region.
Key recovery needs the run's derivation material; residue recovery needs full `plain_*.bin` snapshots.

---

## Validation

[`validation/VALIDATION.log`](validation/VALIDATION.log) records the full-run validation result summarized above: the family's actual encrypted files, decrypted with the key material that run captured.

The repository additionally ships a small, benign synthetic subset.
It checks that the finished recovery tool still handles the represented path; it does not reproduce trace capture or replace the result above.

| Validation scope | Input | Recorded result |
|---|---|---|
| Captured run | the family's encrypted files, with the key material that run captured | `552/558` byte-exact |
| Partial synthetic regression subset | `4` benign originals and `4` synthetic plaintext-residue snapshots for the fallback path | run `validation/run_validation.py` to produce it |

Run from this family directory.
Note that it rewrites `VALIDATION.log` with its own synthetic-subset result, so keep a copy first if the committed run matters to you:

```bash
python validation/run_validation.py
```

## Analysis reports

- **family**: `razrusheniye`
- **execution_quality**: `encrypted_complete`
- **recovery tier**: `RC_MATCHED` (4/7 RC cases passed)
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
