# BlackHunt — RSA key recovery and ChaCha8 decryption

> **Analyzed sample** · SHA-256 `093b4cd8a3f9e456fd7061c2e0f44ce0763aecd9f9ce735adc5da68fa68df6ec` · x86 · ~211 KB · first seen on VT 2024.
> Binary not redistributed — see [analyzed samples](../README.md#analyzed-samples).

## Recovery summary

| RANSACK Reported | Recovery-enabling evidence | Analyst-supplied parameters | Matched RCs | Validated |
|---|---|---|---|---|
| `ChaCha8` | RSA private blob validated by `N = p × q` | RSA validation; wrap/footer/size-tier layout | RC-01, RC-02, RC-03, RC-06, RC-07 | **26/26** byte-exact ([run log](validation/VALIDATION.log)) |

RANSACK reported ChaCha8 and RC-01, RC-02, RC-03, RC-06, and RC-07.
The analyst validated the RSA private blob with `N = p × q`, then established the wrapped material, footer, and size-tier layout required by the recovery tool.

Sources: [report](analysis_report/report.md) · [flow](analysis_report/flow_report.md) · [unified report](analysis_report/unified_report.md) · [source view](analysis_report/sample_view.json) · [recovery details](#recovery-details) · [validation run log](validation/VALIDATION.log)

## Usage

```
python blackhunt_recover.py recover-key --trace <proc_dir> [--out priv.pem]
python blackhunt_recover.py decrypt     --in <enc_dir> --trace <proc_dir> --out <dir> [--ext .LJB8BD3WND] [--mode auto]
python blackhunt_recover.py decrypt-one <file> --trace <proc_dir> --out <dir>
```

- `--trace <proc_dir>` — a BlackHunt trace process dir containing the key-residue `crypto_*.bin` (or pass `--key priv.pem` if you already recovered the key).
- `--in <enc_dir>` — directory of encrypted files **from the same run** (the keypair is per-run).
- `--mode` — `auto` (default) picks the body tier by size: `continuous` (≤512 KiB), `view` (multi-view, 5-byte boundary gaps), `intermittent` (very large, 1 MiB encrypted blocks).

Python 3.10+ with `pycryptodome`.
No internet, no payment.

---

## Recovery details

### RANSACK observations

RANSACK reported `encrypted_complete` and RC-01, RC-02, RC-03, RC-06, and RC-07.
RSA export APIs and 25 plaintext wrap inputs are present, but the asymmetric inventory is empty and the RC-02/03 residue promotion is marked `Audit required`.
The promoted RSA candidate is treated as untrusted until its modulus satisfies `N = p × q`.

### Recovered scheme

Each file uses ChaCha8 with a 32-byte key, an 8-byte nonce, and counter 0.
A 64-byte payload `[key | nonce | unused]` is wrapped with the victim RSA-2048 public key using PKCS#1 v1.5 and stored behind the `RISEN\0` footer marker.
CryptoAPI stores the wrapped block little-endian.

| Tier | Body layout |
|---|---|
| Up to 512 KiB | Continuous ChaCha8 over one mapped view |
| Medium files | Multiple 512 KiB views with a measured 5-byte plaintext gap at view boundaries |
| Large files | Intermittent 1 MiB encrypted blocks separated by plaintext gaps |

### Recovery method

`blackhunt_recover.py` scans the supporting capture for a CryptoAPI private-key candidate, validates `N = p × q`, reconstructs the RSA private key, reverses and unwraps each footer block, and decrypts the body with ChaCha8.
`--mode auto` selects the measured layout by file size.

### Result and limits

The analyzed build recovered **26/26 byte-exact**.
The RSA key is victim/run-specific.
The view gap and large-file cadence were measured on this build; another build may require those layout values to be recalibrated.

---

## Validation

[`validation/VALIDATION.log`](validation/VALIDATION.log) records the full-run validation result summarized above: the family's actual encrypted files, decrypted with the key material that run captured.

The repository additionally ships a small, benign synthetic subset.
It checks that the finished recovery tool still handles the represented path; it does not reproduce trace capture or replace the result above.

| Validation scope | Input | Recorded result |
|---|---|---|
| Captured run | the family's encrypted files, with the key material that run captured | `26/26` byte-exact |
| Partial synthetic regression subset | `4` benign originals, `4` BlackHunt-format inputs, and `1` synthetic RSA private-key capture | run `validation/run_validation.py` to produce it |

Run from this family directory.
Note that it rewrites `VALIDATION.log` with its own synthetic-subset result, so keep a copy first if the committed run matters to you:

```bash
python validation/run_validation.py
```

## Analysis reports

- **family**: `blackhunt`
- **execution_quality**: `encrypted_complete`
- **recovery tier**: `RC_MATCHED` (5/7 RC cases passed)
- **pipeline flags**: NO_PAYLOAD_RUN=`False` · VALIDATED=`False`
- **loop-classifier `primary_cipher`**: `ChaCha8 (Conti body)` (confidence 0.9)
- **pipeline metrics**: Key Detection=`yes` · File Recoverability=`yes` · Loop-Based Behavior Recovery=`yes`

### Report files

| file | what it contains |
|---|---|
| [flow_report.md](analysis_report/flow_report.md) | 10-stage key/cipher/loop flow (Stage 1 identity → Stage 10 Mermaid diagram). |
| [report.md](analysis_report/report.md) | Per-sample verdict, RC-01..07 checklist, and recovery-synthesis evidence (cipher / round count / I/O chunk size). |
| [unified_report.md](analysis_report/unified_report.md) | Consolidated single-page view: identity, recovery verdict, API trace, file ops, loop categories, top-10 scored loops. |
| [sample_view.json](analysis_report/sample_view.json) | Raw flattened view emitted by the report generator — every value rendered into the three reports lives here. |
