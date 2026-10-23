# Recovery Tools

Standalone recovery tools for the thirteen ransomware families analyzed by RANSACK.
Each family directory contains one `README.md` that separates the RANSACK result, the evidence available for recovery, the parameters supplied by the analyst, and the resulting validation.

The malicious samples are not redistributed.
Exact identities are listed under [Analyzed samples](#analyzed-samples).

## Reported evidence and analyst-resolved recovery

**RANSACK Reported** is the cipher emitted by the complete pipeline, not only the loop classifier's `primary_cipher` field.
*h* marks an uncorroborated structural match, *i* marks a primitive inferred from an observed key length by the symmetric-key-inference catalog, `none` means no cipher was identified, and `—` means no RC matched.
**Recovery-enabling evidence** is the artifact that made recovery possible.
**Analyst-supplied parameters** are the scheme, mode, binding, and layout details established while building the tool.
**Validated** is the byte-for-byte recovered fraction; *s* marks an internal-structure check instead.
† marks reference-assisted parameter selection, ‡ marks a separate trace, and ★ marks a re-capture configured to retain additional evidence.
The full corpora are not committed; each family retains its recorded result and a small synthetic regression subset.

| Family | RANSACK Reported | Recovery-enabling evidence | Analyst-supplied parameters | Matched RCs | Validated |
|---|---|---|---|---|---|
| [HDLocker](hdlocker/README.md) | `TEA-16` | Analyst-extracted 73,728-byte `.data` keyspace | Custom CBC; IV = 0 | RC-06 | **74/74** byte-exact |
| [KillRabbit](killrabbit/README.md) | `AES-256-CBC` | 32-byte key from a residue snapshot | IV = 0 | RC-04, RC-06, RC-07 | **40/40** byte-exact |
| [BlackHunt](blackhunt/README.md) | `ChaCha8` | RSA private blob validated by `N = p × q` | RSA validation; wrap/footer/size-tier layout | RC-01, RC-02, RC-03, RC-06, RC-07 | **26/26** byte-exact |
| [WannaCry](wannacry/README.md) | `AES` *h* | Exported RSA private blob validated by `N = p × q` | Key size; CBC; key-to-file binding | RC-01, RC-02, RC-03, RC-06 | **14/14** byte-exact |
| [Everbe](everbe/README.md)<sup>†, ‡</sup> | `AES-NI` *h* | 32-byte key (separate trace) | CBC; IV from a known header† | — | **29/31** byte-exact |
| [Akira](akira/README.md)<sup>†</sup> | `ARX` *h* | 32-byte key and 8-byte nonce at the wrapping sink | ChaCha8†; round count†; byte ranges | RC-07 | **37/38** byte-exact |
| [GarrantyCrypt](garrantycrypt/README.md)<sup>†</sup> | `stream` *h* | RSA private blob validated by `N = p × q` | Salsa20†; chunk layout† | RC-01, RC-02, RC-03, RC-06 | **24/32** byte-exact |
| [Crypt888](crypt888/README.md) | `DES` *i* | 3-byte seed at `CryptHashData` | `MD5("888")[:8]`; CBC; IV = 0; PKCS#7 | RC-04, RC-07 | **37/37** byte-exact |
| [Razrusheniye](razrusheniye/README.md) | `AES-256` *i* | 32-byte key and IV from a residue snapshot | CBC | RC-04, RC-05, RC-06, RC-07 | **552/558** byte-exact |
| [Chaos](chaos/README.md) | `none` | Per-file `KEY\|IV` at the RSA wrapping sink | AES-256; CBC | RC-07 | **510/514** byte-exact |
| [Makop](makop/README.md)<sup>★</sup> | `AES-256` *i* | Provider-boundary sink plaintext | File-type signature; end-marker or NUL trim | RC-05, RC-06, RC-07 | **9/10** structurally recovered *s* |
| [Nitro](nitro/README.md) | `none` | Fixed password from HMAC-pad artifacts | AES-256-CBC; PBKDF2-SHA1, 50k | — | **28/28** byte-exact |
| [AzzaSec](azzasec/README.md)<sup>‡</sup> | `none` | 20-character password (separate trace) | SHA-512-derived AES-256-CBC; PKCS#7 | — | **30/30** byte-exact |

Each family README links every generated report, its recovery details, and the partial validation log.

## Recovery classes

The summary above is the authoritative evidence table.
The groups below only show which artifact makes recovery possible; they do not replace the distinction between **RANSACK Reported** and parameters resolved later by an analyst.

| Recovery class | Families | Required artifact | Scope |
|---|---|---|---|
| Offline, build-scoped source | HDLocker, Crypt888, Nitro | Embedded keyspace, weak seed, or reconstructed builder password | Build-specific; HDLocker's selected key may differ by run |
| Captured symmetric material or pre-image | KillRabbit, Everbe, Akira, Chaos, Razrusheniye, AzzaSec | AES key, password, or plaintext key/nonce at the wrapping sink | Run-specific; Chaos uses a per-file key/IV |
| RSA private-key recovery | WannaCry, BlackHunt, GarrantyCrypt | Candidate private material independently validated with `N = p × q` | Victim/run-specific |
| Plaintext residue | Makop | Plaintext observed at the encryption sink; no key is recovered | Only files present in the instrumented run |

### Evidence boundaries

- Everbe's bundled run reported `indeterminate` / `INFEASIBLE`; separate trace `proc_4108` supplied the AES key, and a known header supplied each IV.
- Akira's ChaCha8 identity and round count were selected with reference assistance after RANSACK reported an ARX structural match and captured the key/nonce material.
- GarrantyCrypt's Salsa20 identity and chunk layout were selected with reference assistance after RANSACK reported a stream structural match and RSA recovery evidence.
- Chaos's bundled report identified no cipher. RANSACK captured per-file `KEY|IV` material and matched RC-07; the analyst subsequently established the 32-byte key/16-byte IV split, AES-256-CBC, file binding, and intermittent layout.
- Nitro's bundled run reported no cipher or RC match; post-report managed-code analysis and HMAC-pad artifacts supplied the password/KDF path.
- AzzaSec's bundled run reported `pin_attach_failed` / `NO_PAYLOAD_RUN`; separate trace `proc_6940` supplied the password.
- WannaCry, BlackHunt, and GarrantyCrypt RSA candidates are accepted only after `N = p × q` validation.

## Included validation subsets

The committed `validation/` directories provide only small, benign synthetic regression subsets.
They exercise the finished recovery tools; they do not reproduce malware execution, trace capture, reverse engineering, or the complete recovery evaluation above.

Run any subset from the repository root:

```bash
python recovery_tools/<family>/validation/run_validation.py
```

| Family | Included subset | Recorded result |
|---|---|---|
| HDLocker | 4 originals + 4 encrypted inputs | 4/4 byte-exact |
| KillRabbit | 4 originals + 4 encrypted inputs + 1 key capture | 4/4 byte-exact |
| BlackHunt | 4 originals + 4 encrypted inputs + 1 RSA private-key capture | 4/4 byte-exact |
| WannaCry | 4 originals + 4 encrypted inputs + 1 RSA private-key capture | 4/4 byte-exact |
| Everbe | 4 originals + 4 encrypted inputs + 1 key capture | 4/4 byte-exact |
| Akira | 4 originals + 4 encrypted inputs + 1 key/nonce capture; modes 0 and 1 | 4/4 byte-exact |
| GarrantyCrypt | 4 originals + 4 encrypted inputs + 1 RSA private-key capture | 4/4 byte-exact |
| Crypt888 | 3 originals + 3 encrypted inputs | 3/3 byte-exact |
| Razrusheniye | 4 originals + 4 plaintext-residue snapshots for the fallback path | 4/4 byte-exact |
| Chaos | 4 originals + 4 encrypted inputs + 1 capture containing four key/IV values | 4/4 byte-exact |
| Makop | 4 originals + 4 plaintext-residue snapshots | 4/4 byte-exact |
| Nitro | 3 originals + 3 encrypted inputs | 3/3 byte-exact |
| AzzaSec | 4 originals + 4 encrypted inputs + 1 password capture | 4/4 byte-exact |
## Analyzed samples

Each recovery tool in this directory was developed and verified against one specific ransomware sample.
The exact binaries are identified below so the analysis and recovery can be **independently reproduced**.

- **The malicious binaries are not redistributed in this repository.** Researchers can obtain each sample from a malware corpus (e.g. VirusTotal, MalwareBazaar / abuse.ch) using the SHA-256 below.
- Metadata is **as reported by VirusTotal** (PE header via *Detect It Easy*).
- **"First seen (VT)"** is the VirusTotal first-submission date of that *specific* sample, **not** the family's emergence date (several of these families are older than the listed year — e.g. WannaCry 2017, Crypt888/MirCop 2016).
- **Arch**: `x86` = 32-bit (PE I386), `x64` = 64-bit (PE Amd64).

| Family | Recovery class | First seen (VT) | Arch | Size | Packed (entropy) | SHA-256 |
|---|---|---|---|---|---|---|
| HDLocker | keyspace brute (TEA) | 2021 | x86 | ~776 KB | yes (8.00) | `b74d0a068b387f7569f9a42729853e742a99ccd71c45946ae153a39eba6b153e` |
| KillRabbit | captured AES-256 key | 2018 | x86 | ~1 MB | yes (6.93) | `d4eb98701bc0c33b5f9c3e202bf55c1b2e2cb1c1e4b7c81ad6305d7938d0f959` |
| BlackHunt | RSA-priv → ChaCha8 | 2024 | x86 | ~211 KB | no (6.14) | `093b4cd8a3f9e456fd7061c2e0f44ce0763aecd9f9ce735adc5da68fa68df6ec` |
| WannaCry | RSA-priv → AES-128-CBC | 2023 | x86 | ~4 MB | yes (7.67) | `fc849725187a811a219d5aecb22ee7d502a0007512386e76899a76be67ebac07` |
| Everbe | captured AES-256 key + known-plaintext IV | 2018 | x64 | ~198 KB | no (6.06) | `14633206a2b1e42d5a960eef94e957100204289333fc60fddc7f704327fec65e` |
| Akira | captured key → ChaCha8 (intermittent) | 2024 | x64 | ~1 MB | — |  `d07b379369e9faea0fed406b9b37652b2fc6453044ab17c1e2189cf61640ab90` |
| GarrantyCrypt | RSA-priv → Salsa20 | 2020 | x86 | ~3 MB | yes (7.98) | `b6e3cdf6757bb325e62cd43f31eb590e8ec63f25674b89ff65d70707af999951` |
| Crypt888 | weak fixed-seed brute (DES) | 2021 | x86 | ~763 KB | yes (6.89) | `481509a67f836e3826fd7835cded0619a1491ed914152d893c6d8ac950445f4f` |
| Razrusheniye | captured symmetric key | 2024 | x64 | ~20 KB | no (5.40) | `c98c470dc1db8a9caba66de0da76fd465685d25e830c30d40cdc422dc9d66bb2` |
| Chaos | captured per-file key\|iv → AES-256-CBC | 2025 | x86 | ~2 MB | — | `a2a703b827fcb58f31e93168b5224543ed9179887cb3f642fdd57e5260ee84d9` |
| Makop | plaintext residue (key-free) | 2022 | x86 | ~42 KB | yes (7.02) | `d0dd0f7658b938f9a3036ce308f5018ae0cf3bc516aaf3c18b947afee136c043` |
| Nitro | build-fixed password → PBKDF2 → AES-256 | 2021 | x86 (.NET) | ~60 KB | — | `d035e86bc527b1bbe1aecee656db2263a0fc130c34a402ef501740c6ad257f7f` |
| AzzaSec | captured password → AES-256 (SHA-512) | 2024 | x86 | ~1 MB | yes (7.07) | `58b45bfd8430d8b24f9142278ff206261ab3d1100b3c98b0fdfcefdddf2fd05d` |

> The recovery class for each family (and the captured evidence it relies on) is described in that family's `README.md` overview and `Recovery details` section.
> SHA-1 is omitted as redundant with SHA-256; the SHA-256 is the canonical identifier for retrieving the sample.

## Adding a family

A family directory should contain the standalone recovery tool, a single `README.md`, the supporting machine-generated `analysis_report/`, and a small `validation/` subset with its runner and last passing log.
The README should follow the same evidence-first order used by the existing families.

## Defensive use

These tools recover files that were already encrypted.
They are intended for victims, incident responders, and academic researchers, not for offensive use.

## Files

| Path | Purpose |
|---|---|
| `<family>/*.py` | Standalone recovery implementation and any family-specific helper. |
| `<family>/README.md` | Family-specific recovery summary, usage, recovery details, validation, and analysis reports. |
| `<family>/analysis_report/` | Machine-generated RANSACK reports and source view for the analyzed run. |
| `<family>/validation/` | Partial synthetic regression subset, runner, and last passing log. |
