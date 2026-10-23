# Crypt888 (MirCop) — Build-scoped DES recovery

> **Analyzed sample** · SHA-256 `481509a67f836e3826fd7835cded0619a1491ed914152d893c6d8ac950445f4f` · x86 · ~763 KB · first seen on VT 2021.
> Binary not redistributed — see [analyzed samples](../README.md#analyzed-samples).

## Recovery summary

| RANSACK Reported | Recovery-enabling evidence | Analyst-supplied parameters | Matched RCs | Validated |
|---|---|---|---|---|
| `DES` *i* | 3-byte seed at `CryptHashData` | `MD5("888")[:8]`; CBC; IV = 0; PKCS#7 | RC-04, RC-07 | **37/37** byte-exact ([run log](validation/VALIDATION.log)) |

RANSACK reported DES by key-length inference and fired RC-04 and RC-07; the loop classifier separately emitted an uncorroborated XOR-stream match.
The three-byte `CryptHashData` seed enabled the analyst to establish `MD5("888")[:8]`, CBC, a zero IV, and PKCS#7 padding.

Sources: [report](analysis_report/report.md) · [flow](analysis_report/flow_report.md) · [unified report](analysis_report/unified_report.md) · [source view](analysis_report/sample_view.json) · [recovery details](#recovery-details) · [validation run log](validation/VALIDATION.log)

## Usage

```bash
# show the key (recovers the 3-byte seed from the trace, else defaults to "888")
python crypt888_recover.py recover-key --trace <proc_dir>

# decrypt a locked folder (key from trace seed, or --seed, or --key <hex>)
python crypt888_recover.py decrypt --in <locked_dir> --out <recovered_dir> --trace <proc_dir>

# unknown-seed variant: brute the 2²⁴ seed against one file's known header
python crypt888_recover.py decrypt --in <locked_dir> --out <recovered_dir> \
       --brute --known-file Lock.photo_1.jpg --known-hex ffd8ff
```
Requires Python 3.10+ with `pycryptodome`.

---

## Recovery details

### RANSACK observations

RANSACK reported DES by inference from the observed 8-byte key length and fired RC-04 and RC-07.
The loop classifier separately reported an uncorroborated XOR-stream structure, so it was not used as the final cipher identity.
The trace also contains the 3-byte `CryptHashData` input used by the CryptoAPI hash/derive chain.

### Recovered scheme

Crypt888 hashes the build seed with MD5, derives a DES key, and encrypts complete files with DES-CBC, IV = 0, and PKCS#7 padding.
The analyzed build uses seed `b"888"`:

- `MD5("888")[:8]` is `0a113ef6b61820da`.
- CryptoAPI's odd-parity form is `0b103ef7b61920da`, the value reported by RC-04.
- The effective DES key bits are the same; the tool accepts the seed or an explicit key.

Encrypted names use the `Lock.` prefix and ciphertext lengths are multiples of DES's 8-byte block size.

### Recovery method

`crypt888_recover.py` can read the 3-byte seed from a trace, use `--seed`, accept `--key`, or brute the 2²⁴ seed space against a known file header.
It derives the DES key, decrypts with CBC/IV 0, removes PKCS#7 padding, and strips `Lock.` from the name.

### Result and limits

The validated corpus recovered **37/37 byte-exact**.
The seed is build-scoped; a build with a different seed needs that seed from its trace or a known-header brute-force.

---

## Validation

[`validation/VALIDATION.log`](validation/VALIDATION.log) records the full-run validation result summarized above: the family's actual encrypted files, decrypted with the key material that run captured.

The repository additionally ships a small, benign synthetic subset.
It checks that the finished recovery tool still handles the represented path; it does not reproduce trace capture or replace the result above.

| Validation scope | Input | Recorded result |
|---|---|---|
| Captured run | the family's encrypted files, with the key material that run captured | `37/37` byte-exact |
| Partial synthetic regression subset | `3` benign originals and `3` Crypt888-format encrypted inputs | run `validation/run_validation.py` to produce it |

Run from this family directory.
Note that it rewrites `VALIDATION.log` with its own synthetic-subset result, so keep a copy first if the committed run matters to you:

```bash
python validation/run_validation.py
```

## Analysis reports

- **family**: `crypt888`
- **execution_quality**: `encrypted_complete`
- **recovery tier**: `RC_MATCHED` (2/7 RC cases passed)
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
