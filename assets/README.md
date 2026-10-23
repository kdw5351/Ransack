# `assets/` — Runtime Rule Catalogs and Evidence

This directory contains the JSON rule catalogs used by the VM-side PIN tool
and the host-side analyzer. Updating a catalog changes detection behavior
without recompiling the project.

Supporting provenance and verification records are kept under
[`rule_evidence/`](rule_evidence/). These Markdown files document where the
rules came from, how catalog fields were derived, and how their citations were
checked; they are not loaded at runtime.

## Layout

```text
assets/
├── crypto_api.json
├── crypto_constants.json
├── dll_roles.json
├── io_activity.json
├── loop_patterns.json
├── sym_key_inference_rules.json
└── rule_evidence/
    ├── RULE_PROVENANCE.md
    ├── RULES_ByteSigScanner.md
    ├── RULES_CryptoConstants.md
    ├── RULES_DLLRoles.md
    ├── RULES_Heavy.md
    ├── RULES_IOActivity.md
    ├── RULES_Light.md
    ├── RULES_LoopPatterns.md
    ├── RULES_RecoveryCases.md
    └── RULES_SymKeyInfer.md
```

[`RULE_PROVENANCE.md`](rule_evidence/RULE_PROVENANCE.md) records the
chronological catalog audit and change history. The remaining `RULES_*.md`
files provide per-rule provenance, source quotations, derivation chains, and
citation-verification results.

## Runtime catalogs

| Catalog | Current rules | Consumer | Purpose |
|---|---:|---|---|
| `crypto_api.json` | 1,013 | VM | Cryptographic API hook definitions and argument layouts: 896 hookable rules and 117 catalog-only reference entries. The host consumes the `kind` already attached to captured events instead of opening this file directly. |
| `crypto_constants.json` | 115 | Host | Cipher, hash, and RSA constants used by the byte-signature scanner. The loader reads the `constants` list; `self_prng_indicators` and `hardcoded_key_indicators` are currently not consumed. |
| `dll_roles.json` | 231 | VM and Host | DLL role classification. The VM uses it for crypto-role tagging and instrumentation exclusions; the host uses it to keep loops in non-crypto modules from receiving cipher labels. Five `_comment_*` keys are documentation, not rules. |
| `io_activity.json` | 157 | VM | File-system, registry, and process API rules used to capture events for the host-side I/O summary. |
| `loop_patterns.json` | 82 | Host | Structural disassembly patterns used to classify cipher, hash, and RNG loops. |
| `sym_key_inference_rules.json` | 14 | Host | Candidate symmetric-key algorithm inference based on observed key-buffer lengths. |

The VM-side loader is implemented in
`onVM/ransomflow/src/rule_catalog.cpp` and receives this directory through
`-rules_dir`. Host-side consumers include `onHost/analysis/analyze_trace.py`
and `onHost/analysis/catalogs.py`.

`dll_roles.json` is the only JSON catalog read on both sides. Hot-loop
capture scope itself does not use that catalog: the VM tracks the main
executable and non-system images using a path filter. DLL-role gating is
applied later when the host classifies captured loops, so a captured loop in a
non-crypto runtime DLL cannot receive a cipher label. Recovery cases fire from
trace evidence rather than family-name lookup.

## Evidence index

Every shipped catalog is covered by a per-rule provenance dump. The evidence
set also covers the recovery-case and byte-signature rules implemented in
Python. A rule cited under several sources has one verdict row per citation,
so a dump can contain more verdict rows than the catalog has rules.

| Rule family | Runtime source | Current rules | Evidence document |
|---|---|---:|---|
| Cryptographic API — Heavy and Light audit passes | `crypto_api.json` | 1,013 | [Heavy](rule_evidence/RULES_Heavy.md), [Light](rule_evidence/RULES_Light.md) |
| Cipher constants | `crypto_constants.json` | 115 | [CryptoConstants](rule_evidence/RULES_CryptoConstants.md) |
| Module roles | `dll_roles.json` | 231 | [DLLRoles](rule_evidence/RULES_DLLRoles.md) |
| File and registry I/O | `io_activity.json` | 157 | [IOActivity](rule_evidence/RULES_IOActivity.md) |
| Loop patterns | `loop_patterns.json` | 82 | [LoopPatterns](rule_evidence/RULES_LoopPatterns.md) |
| Symmetric-key inference | `sym_key_inference_rules.json` | 14 | [SymKeyInfer](rule_evidence/RULES_SymKeyInfer.md) |
| Recovery cases RC-01 through RC-07 | `onHost/analysis/recovery_cases.py` | 7 | [RecoveryCases](rule_evidence/RULES_RecoveryCases.md) |
| Byte-signature scanner | `onHost/analysis/byte_signature_scanner.py` | 6 | [ByteSigScanner](rule_evidence/RULES_ByteSigScanner.md) |

The retired `family_profiles.json` catalog and its
`RULES_FamilyProfiles.md` evidence dump were removed when host-side family
matching was retired.

Some evidence dumps retain historical audit entries for rules that were later
trimmed or de-duplicated. Their phase counts can therefore exceed the current
runtime counts above. In particular, the Heavy and Light passes contain
313 + 928 historical `crypto_api.json` entries, CryptoConstants contains
376 audited entries, IOActivity contains 173, and DLLRoles includes five
non-rule comment entries. These records are retained as audit history rather
than treated as currently shipped rules.

## Reading the evidence

Each rule record identifies its primary source, source quotation or evidence
basis, source URL, and the derivation from that source to the catalog fields.
A `Located at: line:col` citation records where a quotation was found in
fetched source text. Each entry carries one of the following verdicts:

- **OK_LINE_VERIFIED** — the quote matches the source at the listed
  `line:col`.
- **OK_PARTIALLY_LOCATED** — at least one quote is citable; the remainder may
  be paraphrased.
- **OK_QUOTE_NOT_LOCATED** — the source is reachable, but the cited quote was
  not found in the fetched HTML, for example because the page is
  client-rendered or the citation is a non-verbatim paraphrase.
- **DEAD_404_AUTOREPLACED** — the original citation returned 404 and a
  canonical fallback source for the same claim was substituted automatically.
- **DEAD_404_REPLACED_C11** — a live primary source replaced the dead
  citation during the C11 audit pass.
- **DEAD_404_RETRACTED_C11** — the citation was dead, no primary replacement
  was found, and the rule's evidence was retracted.
- **DEAD_404_NO_REPLACEMENT** — no live source remains; the rule needs a new
  citation.
- **BOT_PROTECTED_429** — the source returned HTTP 429 or a bot challenge, so
  the quote could not be machine-located.
- **FORBIDDEN_403** — the source returned HTTP 403 and could not be used for
  line location.
- **SERVER_ERROR_502** — the source returned HTTP 502.
- **UNREACHABLE** — the fetch timed out or raised an operating-system or
  network error.

### Audit-pass codes

Short codes such as `C10`–`C14`, `RETRY`, and the `B-`, `SK-`, or
`HV-` prefixes identify automated verification passes and audit batches.
They are bookkeeping labels rather than properties of a rule.
`FULLY_DERIVED` and `PARTIALLY_DERIVED` indicate how completely the
rule's derivation chain was reconstructed.

### Quote match-quality tags

A located citation also records how its text matched the fetched source:

- `EXACT_SUBSTRING` — the complete quotation matched verbatim.
- `SUBSTRING_30CH` — a 30-character verbatim window matched.
- `TOKEN_OVERLAP_<r>` — the word-token overlap ratio `r` was used when
  the source lightly reflowed the wording.

Match strength is ordered
`EXACT_SUBSTRING` > `SUBSTRING_30CH` > `TOKEN_OVERLAP_<r>`.

### Coverage

Every shipped rule has either an automated, line-cited derivation chain or a
deterministic header-grep line citation. Quarantined symbols that failed
verification were removed from the shipped catalogs.

RecoveryCases is numbered contiguously from RC-01 through RC-07. Two
family-name lookup cases that never fired on trace evidence were removed, and
`cryptoapi_rsa_blob_scan` was added as the sixth ByteSigScanner rule with a
manually verified derivation chain.

## Recovery-case mapping

| Recovery case | Primary rule or evidence source |
|---|---|
| RC-01 — Complete RSA private blob | `crypto_api.json` BCryptExportKey and key-export rules |
| RC-02 — RSA private blob or consistent prime | RSA private-blob and residue signatures in `byte_signature_scanner.py`; a key-generation event is not required |
| RC-03 — Memory-residue prime scan | `crypto_api.json` CryptGenKey plus the 128-byte scanner |
| RC-04 — Limited observed RNG ancestry | Structural untraced-root ratio plus `crypto_api.json` symmetric-key rules |
| RC-05 — Observed RNG-to-keygen path | `crypto_api.json` RNG rules plus chain depth |
| RC-06 — Decisive cipher artifact | Recovery-role-gated constants from `crypto_constants.json` plus heap key-residue signatures |
| RC-07 — Symmetric session-material candidate | `crypto_api.json` symmetric-key rules plus decryption essentials |

See [`RULES_RecoveryCases.md`](rule_evidence/RULES_RecoveryCases.md) for the
full conjunction specification of every recovery case.

## Adding or changing a rule

1. Identify a primary upstream source such as an RFC, FIPS publication,
   vendor header, official reference, or peer-reviewed paper.
2. Copy the relevant signature or source statement verbatim; do not
   paraphrase it as a quotation.
3. Update the appropriate JSON catalog and include its required runtime fields
   plus provenance fields such as `_header_file`, `_header_line`,
   `_header_quote`, and `_source_url` where applicable.
4. Update the corresponding evidence document and record the change in
   [`RULE_PROVENANCE.md`](rule_evidence/RULE_PROVENANCE.md).
5. Reconcile the current rule counts in both the Runtime catalogs and Evidence
   index tables in this README.
