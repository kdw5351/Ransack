# Everbe — AES-256-CBC recovery from a captured key

> **Analyzed sample** · SHA-256 `14633206a2b1e42d5a960eef94e957100204289333fc60fddc7f704327fec65e` · x64 · ~198 KB · not packed (entropy 6.06) · first seen on VT 2018 · trace `proc_4108` (native, no .NET, no C2).
> Binary not redistributed — see [analyzed samples](../README.md#analyzed-samples).

## Recovery summary

| RANSACK Reported | Recovery-enabling evidence | Analyst-supplied parameters | Matched RCs | Validated |
|---|---|---|---|---|
| `AES-NI` *h* | 32-byte key from a separate trace‡ | CBC; IV from a known header† | — | **29/31** byte-exact ([run log](validation/VALIDATION.log)) |

RANSACK reported an uncorroborated AES-NI structural match but no RC match in the bundled run.
A separate trace supplied the 32-byte key, and the analyst established CBC mode and recovered each IV from a known header with reference assistance.

Sources: [report](analysis_report/report.md) · [flow](analysis_report/flow_report.md) · [unified report](analysis_report/unified_report.md) · [source view](analysis_report/sample_view.json) · [recovery details](#recovery-details) · [validation run log](validation/VALIDATION.log)

## Usage

```bash
# recover just the key from the trace
python everbe_recover.py recover-key --in locked/ --trace <proc_dir>

# decrypt every *.eV3rbe (key auto-recovered from the trace)
python everbe_recover.py decrypt --in locked/ --trace <proc_dir> --out recovered/

# or pass the key directly; --known-size gives a byte-exact guarantee when originals' sizes are known
python everbe_recover.py decrypt --in locked/ --key <hex> --out recovered/ --known-size originals/
```
Requires Python 3.10+ and `pycryptodome`.

---

## Recovery details

### Evidence boundary

RANSACK reported `indeterminate` / `INFEASIBLE`, an uncorroborated AES-NI structural match, and no RC match for the bundled run.
That run captured no crypto events, keys, or sinks and does not support decryption by itself.
Separate trace `proc_4108` supplied the 32-byte key, and a known-header method supplied each IV.

### Recovered scheme

Everbe reuses one 32-byte AES-256 key across the run but uses a different 16-byte IV per file.
The body is AES-256-CBC; files up to roughly 1 MiB are fully encrypted, while larger files use a partially encrypted layout.
A roughly 544-byte footer contains per-file metadata and RSA-wrapped material.

### Recovery method

The supporting trace supplies the AES key.
CBC makes blocks after the first independent of the IV; the first IV is recovered from a recognized file header using `IV = AES_dec(key, C0) XOR P0`.
`everbe_recover.py` validates candidates on later blocks, derives the per-file IV, decrypts the represented region, and strips the footer.
`--known-size` is an optional validation aid.

### Result and limits

The analyzed corpus recovered **29/31 byte-exact**.
The two misses are files larger than about 1 MiB; their first encrypted region is recovered but later chunks require additional IV information.
Headerless files recover blocks after the first, but their first 16 bytes require known plaintext.
The run-specific AES key must come from the supporting trace or be supplied directly.

---

## Validation

[`validation/VALIDATION.log`](validation/VALIDATION.log) records the full-run validation result summarized above: the family's actual encrypted files, decrypted with the key material that run captured.

The repository additionally ships a small, benign synthetic subset.
It checks that the finished recovery tool still handles the represented path; it does not reproduce trace capture or replace the result above.

| Validation scope | Input | Recorded result |
|---|---|---|
| Captured run | the family's encrypted files, with the key material that run captured | `29/31` byte-exact |
| Partial synthetic regression subset | `4` benign originals, `4` Everbe-format inputs, and `1` synthetic key capture | run `validation/run_validation.py` to produce it |

Run from this family directory.
Note that it rewrites `VALIDATION.log` with its own synthetic-subset result, so keep a copy first if the committed run matters to you:

```bash
python validation/run_validation.py
```

## Analysis reports

- **family**: `everbe`
- **execution_quality**: `indeterminate`
- **recovery tier**: `INFEASIBLE` (0/7 RC cases passed)
- **pipeline flags**: NO_PAYLOAD_RUN=`False` · VALIDATED=`False`
- **loop-classifier `primary_cipher`**: `AES NI (heuristic, unconfirmed)` (confidence 0.35)
- **pipeline metrics**: Key Detection=`no` · File Recoverability=`no` · Loop-Based Behavior Recovery=`yes`

### Report files

| file | what it contains |
|---|---|
| [flow_report.md](analysis_report/flow_report.md) | 10-stage key/cipher/loop flow (Stage 1 identity → Stage 10 Mermaid diagram). |
| [report.md](analysis_report/report.md) | Per-sample verdict, RC-01..07 checklist, and recovery-synthesis evidence (cipher / round count / I/O chunk size). |
| [unified_report.md](analysis_report/unified_report.md) | Consolidated single-page view: identity, recovery verdict, API trace, file ops, loop categories, top-10 scored loops. |
| [sample_view.json](analysis_report/sample_view.json) | Raw flattened view emitted by the report generator — every value rendered into the three reports lives here. |
