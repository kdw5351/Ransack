# GarrantyCrypt — RSA key recovery and Salsa20 decryption

> **Analyzed sample** · SHA-256 `b6e3cdf6757bb325e62cd43f31eb590e8ec63f25674b89ff65d70707af999951` · x86 · ~3 MB · first seen on VT 2020.
> Binary not redistributed — see [analyzed samples](../README.md#analyzed-samples).

## Recovery summary

| RANSACK Reported | Recovery-enabling evidence | Analyst-supplied parameters | Matched RCs | Validated |
|---|---|---|---|---|
| `stream` *h* | RSA private blob validated by `N = p × q` | Salsa20†; chunk layout† | RC-01, RC-02, RC-03, RC-06 | **24/32** byte-exact ([run log](validation/VALIDATION.log)) |

RANSACK reported an uncorroborated stream structure and RC-01, RC-02, RC-03, and RC-06.
The analyst validated the RSA private blob with `N = p × q`, then used reference assistance to select Salsa20 and establish the chunk layout.

Sources: [report](analysis_report/report.md) · [flow](analysis_report/flow_report.md) · [unified report](analysis_report/unified_report.md) · [source view](analysis_report/sample_view.json) · [recovery details](#recovery-details) · [validation run log](validation/VALIDATION.log)

## Usage

```
python garrantycrypt_recover.py recover-key --trace <proc_dir> [--out priv.pem]
python garrantycrypt_recover.py decrypt     --in <enc_dir> --trace <proc_dir> --out <dir> [--ext .horseleader]
```

`--trace` a GarrantyCrypt trace process dir with the key-residue `crypto_*.bin` (or `--key priv.pem`).
Python 3.10+ with `pycryptodome`.
No internet, no payment.

---

## Recovery details

### RANSACK observations

RANSACK reported `encrypted_complete`, an uncorroborated stream structure, and RC-01, RC-02, RC-03, and RC-06.
RSA export APIs were present, but the promoted private material remained untrusted until `N = p × q` validation.
Salsa20 and the chunk layout were selected with reference assistance rather than directly identified by RANSACK.

### Recovered scheme

Each file uses Salsa20 with a 32-byte key and a 4-byte nonce extended with four zero bytes.
The 36-byte payload is wrapped with a local RSA-1024 public key using PKCS#1 v1.5 and stored in a 132-byte footer.
Encrypted regions are 0x5000-byte chunks and the Salsa20 counter resets to zero for every chunk; skipped regions remain plaintext.

### Recovery method

`garrantycrypt_recover.py` reconstructs the validated RSA private key, reverses the CryptoAPI little-endian footer block, unwraps `[key | nonce]`, and decrypts the computed intermittent chunks with Salsa20.

### Result and limits

The analyzed build recovered **24/32 byte-exact** and restored correct file signatures for all 32.
The eight largest files require middle/end chunk offsets that are not generalized beyond this build.
The RSA key is run-specific, and another build may require its intermittent offsets to be recalibrated.

---

## Validation

[`validation/VALIDATION.log`](validation/VALIDATION.log) records the full-run validation result summarized above: the family's actual encrypted files, decrypted with the key material that run captured.

The repository additionally ships a small, benign synthetic subset.
It checks that the finished recovery tool still handles the represented path; it does not reproduce trace capture or replace the result above.

| Validation scope | Input | Recorded result |
|---|---|---|
| Captured run | the family's encrypted files, with the key material that run captured | `24/32` byte-exact |
| Partial synthetic regression subset | `4` benign originals, `4` GarrantyCrypt-format inputs, and `1` synthetic RSA private-key capture | run `validation/run_validation.py` to produce it |

Run from this family directory.
Note that it rewrites `VALIDATION.log` with its own synthetic-subset result, so keep a copy first if the committed run matters to you:

```bash
python validation/run_validation.py
```

## Analysis reports

- **family**: `garrantycrypt`
- **execution_quality**: `encrypted_complete`
- **recovery tier**: `RC_MATCHED` (4/7 RC cases passed)
- **pipeline flags**: NO_PAYLOAD_RUN=`False` · VALIDATED=`False`
- **loop-classifier `primary_cipher`**: `XOR (stream) (heuristic, unconfirmed)` (confidence 0.35)
- **pipeline metrics**: Key Detection=`yes` · File Recoverability=`yes` · Loop-Based Behavior Recovery=`yes`

### Report files

| file | what it contains |
|---|---|
| [flow_report.md](analysis_report/flow_report.md) | 10-stage key/cipher/loop flow (Stage 1 identity → Stage 10 Mermaid diagram). |
| [report.md](analysis_report/report.md) | Per-sample verdict, RC-01..07 checklist, and recovery-synthesis evidence (cipher / round count / I/O chunk size). |
| [unified_report.md](analysis_report/unified_report.md) | Consolidated single-page view: identity, recovery verdict, API trace, file ops, loop categories, top-10 scored loops. |
| [sample_view.json](analysis_report/sample_view.json) | Raw flattened view emitted by the report generator — every value rendered into the three reports lives here. |
