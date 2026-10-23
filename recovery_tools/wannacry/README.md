# WannaCry — RSA key recovery and AES file decryption

> **Analyzed sample** · SHA-256 `fc849725187a811a219d5aecb22ee7d502a0007512386e76899a76be67ebac07` · x86 · ~4 MB · first seen on VT 2023.
> Binary not redistributed — see [analyzed samples](../README.md#analyzed-samples).

## Recovery summary

| RANSACK Reported | Recovery-enabling evidence | Analyst-supplied parameters | Matched RCs | Validated |
|---|---|---|---|---|
| `AES` *h* | Exported RSA private blob validated by `N = p × q` | Key size; CBC; key-to-file binding | RC-01, RC-02, RC-03, RC-06 | **14/14** byte-exact ([run log](validation/VALIDATION.log)) |

RANSACK reported an uncorroborated AES structural match and RC-01, RC-02, RC-03, and RC-06.
The analyst validated the exported RSA private blob with `N = p × q`, then established the AES key size, CBC mode, and key-to-file binding.

Sources: [report](analysis_report/report.md) · [flow](analysis_report/flow_report.md) · [unified report](analysis_report/unified_report.md) · [source view](analysis_report/sample_view.json) · [recovery details](#recovery-details) · [validation run log](validation/VALIDATION.log)

## Usage

```
python wannacry_recover.py recover-key <proc_dir> [out.pem]            # recover + export the private key
python wannacry_recover.py decrypt     <proc_dir> <enc_dir> [out_dir]  # decrypt every *.WNCRY in enc_dir
```

- `<proc_dir>` — a WannaCry trace process directory containing the key-residue `crypto_*.bin`.
- `<enc_dir>` — directory of `.WNCRY` files **from the same run** (the keypair is per-run).

Python 3.10+ with `pycryptodome`.
No internet, no payment.

---

## Recovery details

### RANSACK observations

RANSACK reported `encrypted_complete` and RC-01, RC-02, RC-03, and RC-06.
It observed RSA export APIs, but the asymmetric inventory was empty and the residue promotion carried false-positive and audit warnings.
Recovery therefore requires an independently validated private-key candidate rather than trusting the RC tier alone.

### Recovered scheme

Each `.WNCRY` file contains a per-file AES-128 key wrapped with the victim RSA-2048 public key, followed by AES-128-CBC ciphertext with IV = 0 and a stored original size.
A usable CryptoAPI private-key candidate contains `N`, `p`, and `q`; `N = p × q` validates it before `d` and the CRT parameters are reconstructed.

### Recovery method

`wannacry_recover.py recover-key` scans the supporting capture for private-key material and exports a validated key.
`decrypt` parses each header, reverses the little-endian 256-byte wrapped block, unwraps it with RSA PKCS#1 v1.5, decrypts the body with AES-128-CBC, and trims to the stored size.

### Result and limits

The analyzed run recovered **14/14 byte-exact**.
The RSA keypair is victim/run-specific and only decrypts files whose AES keys were wrapped with the matching public key.
Recovery requires the corresponding private material to have been captured.

---

## Validation

[`validation/VALIDATION.log`](validation/VALIDATION.log) records the full-run validation result summarized above: the family's actual encrypted files, decrypted with the key material that run captured.

The repository additionally ships a small, benign synthetic subset.
It checks that the finished recovery tool still handles the represented path; it does not reproduce trace capture or replace the result above.

| Validation scope | Input | Recorded result |
|---|---|---|
| Captured run | the family's encrypted files, with the key material that run captured | `14/14` byte-exact |
| Partial synthetic regression subset | `4` benign originals, `4` WannaCry-format inputs, and `1` synthetic RSA private-key capture | run `validation/run_validation.py` to produce it |

Run from this family directory.
Note that it rewrites `VALIDATION.log` with its own synthetic-subset result, so keep a copy first if the committed run matters to you:

```bash
python validation/run_validation.py
```

## Analysis reports

- **family**: `wannacry`
- **execution_quality**: `encrypted_complete`
- **recovery tier**: `RC_MATCHED` (4/7 RC cases passed)
- **pipeline flags**: NO_PAYLOAD_RUN=`False` · VALIDATED=`False`
- **loop-classifier `primary_cipher`**: `AES (S-box, software) (heuristic, unconfirmed)` (confidence 0.35)
- **pipeline metrics**: Key Detection=`yes` · File Recoverability=`yes` · Loop-Based Behavior Recovery=`yes`

### Report files

| file | what it contains |
|---|---|
| [flow_report.md](analysis_report/flow_report.md) | 10-stage key/cipher/loop flow (Stage 1 identity → Stage 10 Mermaid diagram). |
| [report.md](analysis_report/report.md) | Per-sample verdict, RC-01..07 checklist, and recovery-synthesis evidence (cipher / round count / I/O chunk size). |
| [unified_report.md](analysis_report/unified_report.md) | Consolidated single-page view: identity, recovery verdict, API trace, file ops, loop categories, top-10 scored loops. |
| [sample_view.json](analysis_report/sample_view.json) | Raw flattened view emitted by the report generator — every value rendered into the three reports lives here. |
