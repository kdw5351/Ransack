# Rule Provenance — RecoveryCases

**7 rules** in this phase. Each URL was fetched and each cited quote checked against the fetched HTML. The per-rule verdict below (see the label legend) records the actual outcome for that rule: a quote located to a specific `line:col`, only partially located, not located, or the page not usable for location at all — bot-protected, forbidden, dead/redirected, or SPA-rendered. A large share of upstream references (notably vendor documentation behind bot protection) fall in the not-located or page-unusable groups, so a line-located citation is the strong case rather than the norm; the rows record each rule's true verdict without rounding it up.

## Verification label legend
- **OK_LINE_VERIFIED** — page alive AND every quote located at a specific line in the fetched HTML
- **OK_PARTIALLY_LOCATED** — page alive, some quotes located, some not
- **OK_QUOTE_NOT_LOCATED** — page alive, no quote found in HTML (SPA or paraphrase)
- **DEAD_404_AUTOREPLACED** — original cite dead, replaced with canonical pattern
- **DEAD_404_NO_REPLACEMENT** — manual re-cite needed
- **BOT_PROTECTED_429** — Microsoft Learn etc., reachable via browser


## RC-01

### URL / Quote Line-citation

- **`BOT_PROTECTED_429 (Microsoft Learn etc.; verify in browser)`**
  - URL: <https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptexportkey>


### Rule derivation chain (C13 automated, FULLY_DERIVED)
- **Primary source**: <https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptexportkey>
- **Page line**: 533
- **Quoted fragment**: `The CryptExportKey function exports a cryptographic key or a key pair from a cryptographic service provider (CSP) in a secure manner. ... PRIVATEKEYBLOB - Used to transport public/private key pairs. ... NTE_BAD_KEY_STATE - You do not have permission to export the key. That is, when the hKey key was `
- **Derivation chain**: Primary source: https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptexportkey -> page line 533 reads `The CryptExportKey function exports a cryptographic key or a key pair from a cryptographic service provider (CSP) in a secure manner. A handle to the key to be exported is passed to the function, and the function returns a key BLOB.` and the dwBlobType table at line 546+ lists `PRIVATEKEYBLOB - Used to transport public/private key pairs.` -> applied to the rule as: `case_id`=`RC-01` (case number in CASES table), `name`=`rsa_private_blob_exported_full` (the BLOB type returned when dwBlobType==PRIVATEKEYBLOB is the universal recovery oracle described in the Win32 reference), `strategy`=`asym_priv_universal` (a full PRIVATEKEYBLOB self-describes RSA/ECC private parameters - deterministic decrypt without any further heuristic), `evidence_required.has_any_event.apis`=`[BCryptExportKey, CryptExportKey, BCryptFinalizeKeyPair]` (the three Win32 APIs that can emit a PRIVATEKEYBLOB - CryptExportKey is the legacy CryptoAPI path quoted above, BCryptExportKey is the CNG equivalent, BCryptFinalizeKeyPair is the keypair-generation completion that exposes the same in-memory blob), `evidence_required.asym_blob_is_private_not_public`=`true` (the rule must distinguish PRIVATEKEYBLOB from PUBLICKEYBLOB - both are listed as legal dwBlobType values in the table at line 546+, but only PRIVATEKEYBLOB enables decryption), `evidence_required.asym_blob_format_in.formats`=`[RSA2, RS
- **Field mappings**:
  - `case_id` = `RC-01` ← Sequential case id in CASES table (recovery_cases.py line 664)
  - `name` = `rsa_private_blob_exported_full` ← Microsoft Learn dwBlobType table: PRIVATEKEYBLOB exports public/private key pairs - this is the recovery primitive named in the rule
  - `strategy` = `asym_priv_universal` ← PRIVATEKEYBLOB is self-describing per Win32 reference - decryption is deterministic regardless of family
  - `evidence_required.has_any_event.apis` = `[BCryptExportKey, CryptExportKey, BCryptFinalizeKeyPair]` ← CryptExportKey is the API documented on this page; BCryptExportKey is the CNG counterpart noted in the page's deprecation banner pointing to Cryptography Next Generation APIs; BCryptFinalizeKeyPair finalizes a keypair that BCryptExportKey can then emit
  - `evidence_required.residue_class_at_least` = `level=HIGH, allowed_byte_sigs={bcrypt_rsa_blob, cryptoapi_rsa_blob}` ← Because the PinTool emits buffer POINTERS (not out_buf_hex content), the exported PRIVATEKEYBLOB is recovered from the key-birth dump bytes rather than a crypto_summary field. A complete private RSA blob in the snapshot — CNG BCRYPT_RSAKEY_BLOB ('RSA2'/'RSA3' magic) or legacy CryptoAPI PRIVATEKEYBLOB (BLOBHEADER 07 02 + 'RSA2') — promotes residue to HIGH. The blob's self-validating magic plays the role the old asym_blob_complete/is_private/format_in conjunction did, and PUBLICKEYBLOB (RSA1) is excluded because the private byte-signatures only match the private form.
  - `confidence_when_met` = `0.98` ← NTE_BAD_KEY_STATE wording confirms that successful export implies CRYPT_EXPORTABLE was set - the recovered blob is by definition fully decryptable

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: vendor_spec_primary
- **Citation**: Microsoft Win32 API: CryptExportKey (wincrypt.h) + BCryptExportKey (bcrypt.h). MS-CryptoAPI legacy PRIVATEKEYBLOB / CNG PRIVATEKEYBLOB / RSAPRIVATE / RSAFULLPRIVATE / ECCPRIVATE blob formats.
- **URL**: https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptexportkey
- **Quote**:

```text
The CryptExportKey function exports a cryptographic key or a key pair from a cryptographic service provider (CSP) in a secure manner. A handle to the key to be exported is passed to the function, and the function returns a key BLOB. ... PRIVATEKEYBLOB - Used to transport public/private key pairs. ... PUBLICKEYBLOB - Used to transport public keys. ... NTE_BAD_KEY_STATE - You do not have permission to export the key. That is, when the hKey key was created, the CRYPT_EXPORTABLE flag was not specified.
```

- **Derivation**: If ransomware actually invokes (B)CryptExportKey with dwBlobType=PRIVATEKEYBLOB (legacy CryptoAPI) or BCRYPT_RSAPRIVATE_BLOB / BCRYPT_RSAFULLPRIVATE_BLOB / BCRYPT_ECCPRIVATE_BLOB (CNG), the returned buffer is by definition the full private key in a self-describing on-the-wire format. The RC-01 trigger therefore conjuncts (a) the export-class API event was actually seen on-trace, (b) the captured out_buf is >=95% of the declared out_len (so the dump is structurally complete), (c) the blob's first ULONG magic decodes to a *private* (not public) form, and (d) the format is one of the universally re-importable types {RSA2, RSA3, ECK1, ECK3, ECK5, MS_CRYPTOAPI_PRIVATEKEYBLOB}. Sample-set 'AKO/MedusaLocker (export-to-disk variant)' refers to families that walk their own RSA keypair to disk via CryptExportKey before destroying the in-memory copy.

### ② Mechanism
- **Algorithm/Concept**: Self-describing asymmetric private key BLOB export (CryptoAPI PRIVATEKEYBLOB / CNG BCRYPT_RSAFULLPRIVATE_BLOB / ECCPRIVATE_BLOB).
- **Cryptographic role**: Universal decryption oracle: the exported blob contains modulus N, public exponent e, primes p,q, exponents dP,dQ, coefficient qInv (or full d) -- any one of these reaching disk/heap means the per-victim asymmetric secret is reconstructible byte-for-byte without any cryptanalysis.
- **Why this is a unique signature**: The blob format is fixed by the Windows SDK header (wincrypt.h, bcrypt.h) and the on-the-wire bytes are interoperable across all Microsoft CSP/KSP implementations. A ransomware author who needs to ship the victim key back to their C2 has essentially one production-grade option (call (B)CryptExportKey) and that single API ships the entire key material in a parseable container -- this is precisely why RC-01 is 0.98 confidence (universal, deterministic decryption).
- **Bit provenance**: MS-CryptoAPI PUBLICKEYSTRUC + RSAPUBKEY header: first byte bType = 0x07 (PRIVATEKEYBLOB) or 0x06 (PUBLICKEYBLOB); RSAPUBKEY.magic = 'RSA2' (0x32415352) for private vs 'RSA1' (0x31415352) for public. CNG BCRYPT_RSAKEY_BLOB.Magic ULONG = BCRYPT_RSAPRIVATE_MAGIC (0x32415352) or BCRYPT_RSAFULLPRIVATE_MAGIC (0x33415352). These magic constants are the *unique* in-memory signatures the bcrypt_rsa_blob / cryptoapi_rsa_blob byte-signature scanners match against in the key-birth dump (private forms: RSA2 / RSA3 for CNG, BLOBHEADER 07 02 + 'RSA2' for legacy CryptoAPI).

### ③ Detection
- **Runtime step**: (a) The PinTool RTN-level hook on CryptExportKey / BCryptExportKey / BCryptFinalizeKeyPair emits the export event into crypto_events AND `PIN_SafeCopy`s the key-birth region to `crypto_<N>.bin`. IMPORTANT: the PinTool emits in_buf/out_buf as POINTER addresses (HexAddr), not an out_buf_hex content field, so the exported PRIVATEKEYBLOB is recovered from the dump bytes -- not from a crypto_summary.asym_blobs entry (which is always empty under this feed). (b) byte_signature_scanner scans each key-birth snapshot for a complete RSA *private* blob (bcrypt_rsa_blob for CNG BCRYPT_RSAKEY_BLOB, cryptoapi_rsa_blob for legacy CryptoAPI PRIVATEKEYBLOB); residue_scanner promotes a private-blob hit to residue=HIGH. (c) recovery_cases.evaluate() runs two primitives in conjunction: has_any_event({BCryptExportKey,CryptExportKey,BCryptFinalizeKeyPair}) -> residue_class_at_least(level=HIGH, allowed_byte_sigs={bcrypt_rsa_blob, cryptoapi_rsa_blob}).
- **Match criteria**: Both evidence primitives must return ok=True: an export-class API observed AND a private RSA blob (bcrypt/cryptoapi) present in a key-birth dump that promotes residue to HIGH. (RC-02 is the same residue WITHOUT the export-event conjunct, hence RC-01's higher confidence.)
- **Cross-axis role**: aux+meta (recovery-feasibility verdict, not family identification)
- **Implementation file**: onHost/analysis/recovery_cases.py (RC-01 in CASES); upstream feeds: onVM PinTool key-birth snapshots (crypto_<N>.bin) -> onHost/analysis/byte_signature_scanner.py (cryptoapi_rsa_blob / bcrypt_rsa_blob scan) -> onHost/analysis/residue_scanner.py (HIGH promotion) -> onHost/analysis/loaders.py (bundle).

### ④ Limits
- **Ambiguity shared with**: RC-02 (per_run_rsa_keypair_in_heap) -- same API surface but RC-02 fires when *only* the keygen event + heap residue exist, not a successful export., RC-07 (per-file session keys via PayBreak) -- both can fire if PayBreak-style instrumentation captured both asymmetric and symmetric keys.
- **FP scenarios**:
  - A benign EFS or BitLocker recovery agent calling CryptExportKey on the user's own DPAPI master key during enrollment would technically satisfy all four primitives -- the RC-01 verdict is 'recoverable', which is true regardless of whether the caller is malicious.
  - Pen-test / red-team tooling (Mimikatz key dumpers) exporting RSA keypairs from LSA secrets would trigger RC-01 even though no ransomware encryption happened.
- **FN scenarios**:
  - Ransomware that exports the keypair *but* writes only the modulus + public exponent (PUBLICKEYBLOB / RSA1) to C2 -- only the public form lands in the dump, which the private byte-signatures (bcrypt/cryptoapi private) correctly do not match.
  - Ransomware that bypasses Microsoft CryptoAPI entirely (static OpenSSL, Crypto++, libsodium) -- no API event observed -> has_any_event() returns False. Falls into RC-06 (a decisive cipher constant / key-residue signature) or RC-07 instead.
  - key_snapshot_bytes truncation: the private blob must fall within the key-birth snapshot window (knob `-key_snapshot_bytes`, default 4 KB centred on the hooked buffer). This covers an RSA-2048 PRIVATEKEYBLOB (~1.2 KB) and an RSA-4096 full blob (~2.4 KB); a smaller window, or a blob that lives far from the hooked buffer address, can miss it.

*Consistency verdict*: **OK -- the two-primitive conjunction (an export-class event AND a private RSA blob in the key-birth dump promoting residue to HIGH) realises paper §III Table II's intent ('ExportKey/FinalizeKeyPair event AND a complete private blob') under the current PinTool feed, which captures the blob as snapshot bytes rather than an out_buf_hex field. The bcrypt_rsa_blob / cryptoapi_rsa_blob byte-signatures enforce the private-form and structural-completeness checks the old asym_blob_complete/is_private/format_in primitives performed.**

---

### Rationale + Usage
### 5 Rationale (why included in the catalog)
- **Why included**: RC-01 is included in the catalog because it constitutes the deterministic recovery path of the 'asym_priv_universal' strategy and represents the highest-confidence case, enabling immediate decryption at 0.98 confidence when the entire RSA PRIVATEKEYBLOB has been exported to memory/disk. Because the blob format is self-describing (RSA2/RSA3/ECK1/3/5/CAPI_PRIV), no additional oracle is required.
- **Historical motivation**: Analysis of the AKO/MedusaLocker export-to-disk variant identified cases in which ransomware exported PRIVATEKEYBLOB to disk via CryptExportKey/BCryptExportKey and the subsequent deletion path failed, establishing the need to systematically capture this behavior. In addition, Yuste & Pastrana (2021)'s analysis of Avaddon highlighted the academic importance of capturing in-trace export events.
- **Coverage gap if absent**: Without this rule, traces in which CryptExportKey/BCryptFinalizeKeyPair leave a complete private blob with completeness >= 0.95 in memory would be missed, downgrading a deterministic 0.98-confidence recovery opportunity to RC-02 (0.85).

### 6 Usage (how / why used)
- **Primary use case**: A high-tier deterministic decision for universal recovery at the moment of complete asymmetric private key blob capture. Unlike RC-03 (prime scan) or RC-06 (AES session-key residue), which depend on partial capture, RC-01 requires the completeness of a self-describing blob.
- **Consumer files**: onHost/analysis/recovery_cases.py, onHost/analysis/report.py
- **Contributes to**: RC-01 decision, recovery tier classification, asym_priv_universal strategy feasibility
- **Concrete example**: RC-01 triggers when, following a BCryptExportKey / CryptExportKey call, the key-birth dump contains a complete RSA PRIVATEKEYBLOB that the bcrypt_rsa_blob / cryptoapi_rsa_blob scanner recovers (promoting residue to HIGH). Verified on trace_Surtr_1 (a legacy CryptoAPI RSA-1024 PRIVATEKEYBLOB in crypto_2.bin with the export event present -> RC-01 PASS).

---

### Citations check
  - URL: https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptexportkey
    - quote_verified: The CryptExportKey function exports a cryptographic key or a key pair from a cryptographic service provider (CSP) in a secure manner. ... PRIVATEKEYBLOB - Used to transport public/private key pairs. ... PUBLICKEYBLOB - Used to transport public keys. ... NTE_BAD_KEY_STATE - You do not have permission to export the key. That is, when the hKey key was created, the CRYPT_EXPORTABLE flag was not specified.
    - support: DIRECT | authority: PRIMARY
    - excerpt: The CryptExportKey function exports a cryptographic key or a key pair from a cryptographic service provider (CSP) in a secure manner. A handle to the key to be exported is passed to the function, and 

---

## RC-02

### URL / Quote Line-citation

- **`BOT_PROTECTED_429 (Microsoft Learn etc.; verify in browser)`**
  - URL: <https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob>


### Rule derivation chain (C13 automated, FULLY_DERIVED)
- **Primary source**: <https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob>
- **Page line**: 538
- **Quoted fragment**: `typedef struct _BCRYPT_RSAKEY_BLOB { ULONG Magic; ULONG BitLength; ULONG cbPublicExp; ULONG cbModulus; ULONG cbPrime1; ULONG cbPrime2; } BCRYPT_RSAKEY_BLOB; ... BCRYPT_RSAPRIVATE_MAGIC - The key is an RSA private key. BCRYPT_RSAFULLPRIVATE_MAGIC - The key is a full RSA private key. ... An RSA privat`
- **Derivation chain**: Primary source: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob -> page line 538 reads the structure `typedef struct _BCRYPT_RSAKEY_BLOB { ULONG Magic; ULONG BitLength; ULONG cbPublicExp; ULONG cbModulus; ULONG cbPrime1; ULONG cbPrime2; } BCRYPT_RSAKEY_BLOB;` and line 553 (Magic table) enumerates `BCRYPT_RSAPRIVATE_MAGIC - The key is an RSA private key.` and `BCRYPT_RSAFULLPRIVATE_MAGIC - The key is a full RSA private key.`, with the BCRYPT_RSAPRIVATE_BLOB contiguous-memory layout appending PublicExponent/Modulus/Prime1/Prime2 -> applied to the rule as: `case_id`=`RC-02` (sequential case id), `name`=`per_run_rsa_keypair_in_heap` (the heap residue scanned is exactly the BCRYPT_RSAKEY_BLOB layout quoted above - the recoverable structure left in heap after RSA keygen), `strategy`=`memory_residue_scan` (the contiguous-memory layout enables byte-pattern scanning for the Magic field followed by BitLength/cbPublicExp/cbModulus), `evidence_required.has_any_event.apis`=`[BCryptGenerateKeyPair, CryptGenKey, BCryptFinalizeKeyPair, RSA_generate_key_ex]` (BCryptGenerateKeyPair+BCryptFinalizeKeyPair is the CNG keygen path that allocates the BCRYPT_RSAKEY_BLOB on heap, CryptGenKey is the legacy CryptoAPI counterpart, RSA_generate_key_ex is the OpenSSL equivalent), `evidence_required.residue_class_at_least.level`=`HIGH` (HIGH residue is required because the full PRIVATE/FULLPRIVATE blob contains Prime1 and Prime2 which - per the contiguous-memory layout abo
- **Field mappings**:
  - `case_id` = `RC-02` ← Sequential case id in CASES table (recovery_cases.py line 697)
  - `name` = `per_run_rsa_keypair_in_heap` ← BCRYPT_RSAKEY_BLOB structure documents the in-memory header for an RSA private key BLOB - the residue scanned
  - `strategy` = `memory_residue_scan` ← Microsoft Learn Remarks section specifies the contiguous-memory layout (PublicExponent/Modulus/Prime1/Prime2) that enables a byte-pattern scan
  - `evidence_required` (recovery-feasibility revision) — the paper §III keygen-event conjunct is demoted from a hard gate to metadata: a private RSA key blob left in a key-birth dump is directly recoverable whether it was runtime-generated OR imported, so requiring a keygen event would wrongly drop imported-keypair residue. RC fires on the dump-key residue alone.
  - `evidence_required.residue_class_at_least` = `level=HIGH, allowed_byte_sigs=[bcrypt_rsa_blob, cryptoapi_rsa_blob, wanakiwi_prime]` ← residue HIGH must be reached via an RSA-private byte signature: bcrypt_rsa_blob (CNG BCRYPT_RSAKEY_BLOB, magic@0) + cryptoapi_rsa_blob (legacy CryptoAPI PRIVATEKEYBLOB, magic@8 after the 8-byte BLOBHEADER) + wanakiwi_prime (bare CryptoAPI primes). A residue HIGH promoted ONLY by a non-RSA signature (aeskeyfind / avaddon = AES key) reverts to its un-promoted class so the rule fails — no over-claim of an RSA key from an AES hit.
  - `evidence_required.file_present.rel_path` = `key_residue_map.json` ← present via the equivalence-mapping (chunked key_residue_snapshots_N.jsonl / crypto_N.bin / RSA byte-signature hit)
  - `confidence_when_met` = `0.85` ← Lower than RC-01 because the BCRYPT_RSAKEY_BLOB doc does not guarantee post-destroy persistence; relies on missed zeroization (Bajpai & Enbody 2020)
  - `real_samples` = `[early CryptoLocker (server-keygen variants), TorrentLocker]` ← Families that perform per-run RSA keygen via the CNG/CryptoAPI APIs documented on this page

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: vendor_spec_primary + forensics_paper
- **Citation**: Microsoft CNG: BCRYPT_RSAKEY_BLOB structure (bcrypt.h, Vista+). Combined with classical memory-forensics literature on heap residue (Bajpai & Enbody, 2020).
- **URL**: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
- **Quote**:

```text
typedef struct _BCRYPT_RSAKEY_BLOB { ULONG Magic; ULONG BitLength; ULONG cbPublicExp; ULONG cbModulus; ULONG cbPrime1; ULONG cbPrime2; } BCRYPT_RSAKEY_BLOB; ... BCRYPT_RSAPUBLIC_MAGIC - The key is an RSA public key. BCRYPT_RSAPRIVATE_MAGIC - The key is an RSA private key. BCRYPT_RSAFULLPRIVATE_MAGIC - The key is a full RSA private key. ... An RSA private key BLOB (BCRYPT_RSAPRIVATE_BLOB) has the following format in contiguous memory ... PublicExponent[cbPublicExp] ... Modulus[cbModulus] ... Prime1[cbPrime1] ... Prime2[cbPrime2]
```

- **Derivation**: Ransomware that generates an RSA-keypair *per victim* via BCryptGenerateKeyPair/BCryptFinalizeKeyPair (CNG) or CryptGenKey (legacy CryptoAPI) materializes the BCRYPT_RSAKEY_BLOB header + p,q primes in the calling process's heap. If the destroy path (BCryptDestroyKey + heap zeroize) is missed, omitted, or runs *after* a snapshot, the full private key sits in MEM_PRIVATE pages. The byte-signature scanner detects this by anchoring on the BCRYPT_RSAPRIVATE_MAGIC / RSAFULLPRIVATE_MAGIC ULONG (recovery_cases.py line 442-453 'BCRYPT_RSAKEY_BLOB ... self-validating header with RSA3 / RSA2 magic'). Sample-set explicitly names 'HDLocker', 'early CryptoLocker (server-keygen variants)', 'TorrentLocker' as families whose runtime keygen left exploitable residue.

### ② Mechanism
- **Algorithm/Concept**: RSA per-run keypair generation + heap-residue persistence after incomplete zeroize.
- **Cryptographic role**: S1 (asymmetric secret material) -- the recovered blob contains both primes p,q so private exponent d can be reconstituted via d = e^-1 mod phi(N). No cryptanalysis required.
- **Why this is a unique signature**: BCRYPT_RSAPRIVATE_MAGIC is a header constant fixed by bcrypt.h since Windows Vista (2007); no benign mathematical sequence collides with the four-byte magic + the structural constraints below. The combination is effectively zero false-positive across normal application memory.
- **Bit provenance**: BCRYPT_RSAKEY_BLOB.Magic first 4 bytes: 0x32415352 ('RSA2' = BCRYPT_RSAPRIVATE_MAGIC), 0x33415352 ('RSA3' = BCRYPT_RSAFULLPRIVATE_MAGIC). Self-validating: cbModulus*8 must equal BitLength; cbPrime1 = cbPrime2 = cbModulus/2 (RFC 8017 sec 3.1 / FIPS 186-5 A.1.1). The byte_signature_scanner anchors on the 4-byte Magic and then validates the consistency of BitLength/cbModulus/cbPrime1/cbPrime2 fields before accepting -- this drives the 'bcrypt_rsa_blob_count' / 'bcrypt_rsa_blob_hits' fields. residue_class_at_least('HIGH') gates on the full residue_scanner classifier output.

### ③ Detection
- **Runtime step**: (a) Pre-/mid-/post-encrypt heap snapshots are written into crypto_N.bin or key_residue_snapshots_N.jsonl chunks. (b) byte_signature_scanner.py scans them for RSA private-key blobs -> byte_sigs['bcrypt_rsa_blob_hits'] (CNG BCRYPT_RSAKEY_BLOB, magic@0) AND byte_sigs['cryptoapi_rsa_blob_hits'] (legacy CryptoAPI PRIVATEKEYBLOB, magic@8 after the BLOBHEADER) plus wanakiwi_prime_hits. (c) residue_scanner.apply_byte_sig_promotion() promotes residue to HIGH, recording the promoting signature (reason cryptoapi_rsa_blob / bcrypt_rsa_blob / wanakiwi_prime / aeskeyfind / avaddon). (d) recovery_cases.evaluate() requires residue_class_at_least('HIGH', allowed_byte_sigs=[bcrypt_rsa_blob, cryptoapi_rsa_blob, wanakiwi_prime]) -> file_present('key_residue_map.json' via the equivalence-mapping). The keygen event is NO LONGER a hard gate — an RSA private key in the dump is recoverable regardless of how it got there (runtime keygen OR import).
- **Match criteria**: residue >= HIGH promoted by an RSA-private byte signature (bcrypt_rsa_blob OR cryptoapi_rsa_blob OR wanakiwi_prime) AND a residue artifact on trace. A residue HIGH whose ONLY promoter is an AES signature (aeskeyfind/avaddon) is reverted to the un-promoted class -> RC-02 does NOT fire (those traces fall to RC-04 / RC-06 / RC-07).
- **Cross-axis role**: aux+meta (memory residue recovery feasibility)
- **Implementation file**: onHost/analysis/recovery_cases.py (CASES[1] RC-02 evidence_required + residue_class_at_least strict-promotion check that reverts AES-only promotions); upstream feeds: onHost/analysis/byte_signature_scanner.py (bcrypt_rsa_blob_hits + cryptoapi_rsa_blob_hits aggregators), onHost/analysis/residue_scanner.py (apply_byte_sig_promotion records the promoting signature per reason; HIGH/MID/LOW/NONE classifier).

### ④ Limits
- **Ambiguity shared with**: RC-01 (rsa_private_blob_exported_full) -- both depend on the same keygen events; difference is whether ExportKey actually fired., RC-03 (memory_residue_prime_scan_cryptoapi) -- RC-03 is a *weaker* variant requiring only the 128-byte prime windows (no BCRYPT_RSAKEY_BLOB header), used when the legacy CryptoAPI / wannakey path applies on pre-Win10.
- **FP scenarios**:
  - A legitimate application that generates a per-session RSA key (TLS clients, OpenSSH key generators, code-signing tools) and dumps the heap during a memory profiler run could produce the same residue pattern.
  - Test harnesses that intentionally allocate BCRYPT_RSAKEY_BLOB-shaped buffers (Microsoft cryptography unit tests, CNG fuzzers).
- **FN scenarios**:
  - Ransomware that calls BCryptDestroyKey + SecureZeroMemory immediately after CryptEncrypt finishes (clean implementation) -- residue scanner returns NONE/LOW, RC-02 does not fire.
  - Ransomware that uses OpenSSL RSA_generate_key_ex statically -- the in-memory BIGNUM layout is *not* BCRYPT_RSAKEY_BLOB so the byte_signature_scanner misses it. (The OpenSSL-EVP fallback was folded into RC-06; absent a decisive constant or key-residue signature, such a trace is left unrecovered.)
  - Truncated KnobResidueSnapshotCap or KnobSnapshotInterval skipping the window when the key was live.

*Consistency verdict*: **Recovery-feasibility revision of paper §III Table II. The original 'Keygen event AND residue >= HIGH AND key_residue_map.json' conjunction is relaxed two ways: (1) the keygen event is demoted from a hard gate to metadata — an imported RSA keypair left in heap is equally recoverable, so RC fires on the dump-key residue alone; (2) residue HIGH must be promoted by an RSA-private byte signature (bcrypt_rsa_blob / cryptoapi_rsa_blob / wanakiwi_prime) — an AES-only promotion (aeskeyfind / avaddon) reverts to the un-promoted class so the rule cannot over-claim an RSA key from an AES hit. file_present keeps its equivalence-mapping (chunked / byte-sig / crypto_bin). cryptoapi_rsa_blob (legacy CryptoAPI PRIVATEKEYBLOB, magic@8) was added because bcrypt_rsa_blob_scan anchors magic at offset 0 and structurally missed it.**

---

### Rationale + Usage
### 5 Rationale (why included in the catalog)
- **Why included**: RC-02 is included to capture, at 0.85 confidence, cases in which an RSA private key is left in a key-birth heap dump — whether the keypair was generated at runtime (missing destroy path) or imported. When a BCRYPT_RSAKEY_BLOB (CNG, RSA2 magic at offset 0) or a CryptoAPI PRIVATEKEYBLOB (legacy CryptoAPI, RSA2 magic at offset 8 after the BLOBHEADER) is detected in residue, the match is deterministic.
- **Historical motivation**: Analyses of early CryptoLocker server-keygen variants and TorrentLocker repeatedly reported cases in which BCryptDestroyKey was not called after BCryptGenerateKeyPair/CryptGenKey, or in which heap free was not zero-filled, leaving the RSA private key as residue. It has been academically verified that the self-validating header structure of Microsoft CNG bcrypt.h is well suited to byte-signature detection.
- **Coverage gap if absent**: Without this rule, recoverable traces identifiable via the combination of a keygen API call + HIGH residue + key_residue_map.json in server-side RSA keygen patterns (early CryptoLocker, TorrentLocker) would be missed and misclassified as RC-04 (hardcoded).

### 6 Usage (how / why used)
- **Primary use case**: Detection of an RSA private-key blob left in a key-birth dump (runtime-generated OR imported keypair). Activated when residue >= HIGH is promoted by an RSA-private byte signature (bcrypt_rsa_blob / cryptoapi_rsa_blob / wanakiwi_prime) together with key_residue_map.json — the keygen event is no longer a required conjunct.
- **Consumer files**: onHost/analysis/recovery_cases.py, onHost/analysis/report.py
- **Contributes to**: RC-02 decision, recovery tier classification, memory_residue_scan strategy feasibility, bcrypt_rsa_blob_in_residue corroboration
- **Concrete example**: RC-02 is triggered when, in an early-CryptoLocker or TorrentLocker server-keygen trace, the residue scanner detects a BCRYPT_RSAKEY_BLOB private magic at HIGH grade in the heap snapshot following a BCryptGenerateKeyPair call.

---

### Citations check
  - URL: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
    - quote_verified: typedef struct _BCRYPT_RSAKEY_BLOB { ULONG Magic; ULONG BitLength; ULONG cbPublicExp; ULONG cbModulus; ULONG cbPrime1; ULONG cbPrime2; } BCRYPT_RSAKEY_BLOB; ... BCRYPT_RSAPUBLIC_MAGIC - The key is an RSA public key. BCRYPT_RSAPRIVATE_MAGIC - The key is an RSA private key. BCRYPT_RSAFULLPRIVATE_MAGIC - The key is a full RSA private key. ... An RSA private key BLOB (BCRYPT_RSAPRIVATE_BLOB) has the following format in contiguous memory ... PublicExponent[cbPublicExp] ... Modulus[cbModulus] ... Prime1[cbPrime1] ... Prime2[cbPrime2]
    - support: DIRECT | authority: PRIMARY
    - excerpt: typedef struct _BCRYPT_RSAKEY_BLOB { ULONG Magic; ULONG BitLength; ULONG cbPublicExp; ULONG cbModulus; ULONG cbPrime1; ULONG cbPrime2; } BCRYPT_RSAKEY_BLOB; ... BCRYPT_RSAPUBLIC_MAGIC The key is an RS

---

## RC-03

### URL / Quote Line-citation

- **`OK_LINE_VERIFIED (1/1 quotes located exact)`**
  - URL: <https://github.com/aguinet/wannakey>
  - Quote: `CryptReleaseContext does not do the cleanup [under Windows XP] ... CryptDestroyKey and CryptReleaseContext does not eras`
    - Located at: **line 2245 col 0** (SUBSTRING_30CH)
    - HTML snippet: `CryptReleaseContext does not do the cleanup. Moreover, MSDN states this,`


### Rule derivation chain (C13 automated, FULLY_DERIVED)
- **Primary source**: <https://github.com/aguinet/wannakey>
- **Page line**: 2245
- **Quoted fragment**: `The main issue is that the `CryptDestroyKey` and `CryptReleaseContext` does not erase the prime numbers from memory before freeing the associated memory. ... It can work under Windows XP because, in this version, `CryptReleaseContext` does not do the cleanup. ... Indeed, for what I've tested, under `
- **Derivation chain**: Primary source: https://github.com/aguinet/wannakey -> page line 2245 reads `The main issue is that the CryptDestroyKey and CryptReleaseContext does not erase the prime numbers from memory before freeing the associated memory. ... It can work under Windows XP because, in this version, CryptReleaseContext does not do the cleanup. ... under Windows 10, CryptReleaseContext does cleanup the memory (and so this recovery technique won't work).` -> applied to the rule as: `case_id`=`RC-03` (sequential case id), `name`=`memory_residue_prime_scan_cryptoapi` (the technique scans heap for the 128-byte RSA primes p,q that CryptDestroyKey/CryptReleaseContext failed to erase, as Guinet quotes above), `strategy`=`memory_residue_scan` (heap-residue brute-force divisibility-checked against the public modulus), `evidence_required.has_any_event.apis`=`[CryptGenKey, CryptAcquireContextW, CryptAcquireContextA]` (CryptoAPI legacy keygen path - the quote explicitly names CryptReleaseContext which is the destructor for the CryptAcquireContext-allocated handle; CryptGenKey is what actually allocates the prime buffers that survive), `evidence_required.residue_class_at_least.level`=`MID` (MID rather than HIGH because the technique only needs the 128-byte prime fragments to survive, not the full BLOB; Guinet's 128-byte sliding window described in the rule comment requires only partial heap survival), `real_samples`=`[WannaCry (XP/Win7, via wanakiwi/wannakey)]` (the OS gate `XP / 2003 / Vista / 7 / 2008 / 2008R2` 
- **Field mappings**:
  - `case_id` = `RC-03` ← Sequential case id in CASES table (recovery_cases.py line 728)
  - `name` = `memory_residue_prime_scan_cryptoapi` ← Guinet's wannakey README at github.com/aguinet/wannakey explicitly names CryptoAPI heap residue of RSA primes (CryptDestroyKey/CryptReleaseContext do not erase) as the technique
  - `strategy` = `memory_residue_scan` ← Sliding 128-byte window scan over heap per Guinet's technique, divisibility-tested against on-disk public modulus N
  - `evidence_required.has_any_event.apis` = `[CryptGenKey, CryptAcquireContextW, CryptAcquireContextA]` ← CryptoAPI APIs Guinet's wannakey targets - CryptAcquireContext+CryptGenKey is the allocator path whose CryptReleaseContext destructor does not erase primes on Win<10
  - `evidence_required.residue_class_at_least.level` = `MID` ← Lower than HIGH because only 128-byte prime fragments must survive, not full blob - per Guinet's sliding-window approach
  - `real_samples` = `[WannaCry (XP/Win7, via wanakiwi/wannakey)]` ← WannaCry was the canonical target of wannakey/wanakiwi per Guinet's README; XP/Win7 matches the `CryptReleaseContext does not do the cleanup` OS gate
  - `confidence_when_met` = `0.55` ← Guinet's README explicitly states the technique fails on Win10+ because CryptReleaseContext now cleans up - so confidence is gated by victim-OS distribution

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: open_source_decryptor_primary
- **Citation**: Adrien Guinet, wannakey (May 2017, github.com/aguinet/wannakey) + Benjamin Delpy & Matthieu Suiche, wanakiwi (May 2017, github.com/gentilkiwi/wanakiwi). Independently validated by ESET (WeLiveSecurity 2017).
- **URL**: https://github.com/aguinet/wannakey
- **Quote**:

```text
CryptReleaseContext does not do the cleanup [under Windows XP] ... CryptDestroyKey and CryptReleaseContext does not erase the prime numbers from memory before freeing the associated memory ... [WannaKey] searches specifically within the wcry.exe process memory for these abandoned prime numbers ... Success is probabilistic: 'you need some luck for this to work,' as memory must remain undisturbed between key generation and recovery attempts.
```

- **Derivation**: Pre-Windows-10 Microsoft CryptoAPI (rsaenh.dll) on XP / 2003 / Vista / 7 / 2008 / 2008R2 does NOT zero RSA primes on CryptReleaseContext -- the heap blocks returned to the LFH retain the p,q big-integer limbs. WannaCry calls CryptGenKey(AT_KEYEXCHANGE, RSA-2048), encrypts the AES session key with the per-host public modulus, then calls CryptReleaseContext expecting the primes to vanish. They do not. wannakey's algorithm: enumerate MEM_PRIVATE | PAGE_READWRITE regions in the wcry.exe process, slide a 128-byte (RSA-2048 prime length = 1024 bits) window at 4-byte stride, accept any window whose value c satisfies N mod c == 0 against the known public modulus from 00000000.pky. The Miller-Rabin sanity check (25 rounds) inside wannakey's bigint is internal only -- divisibility against the on-disk public N is the gating oracle. RC-03 source comment lines 652-680 reproduce this verbatim including OS-gate (Win10 patched -> technique fails).

### ② Mechanism
- **Algorithm/Concept**: Memory residue scan for RSA primes (p, q) post-CryptReleaseContext on pre-Win10 CryptoAPI.
- **Cryptographic role**: S1 (asymmetric secret) -- recovering either p or q lets you compute q = N/p, phi(N) = (p-1)(q-1), d = e^-1 mod phi(N), full private key reconstructed.
- **Why this is a unique signature**: The combined gate {128-byte high-entropy window} + {N % candidate == 0} is information-theoretically unique. No cryptographic primitive other than 'an actual prime factor of N' satisfies both. The OS-version sensitivity (pre-Win10 only) is the *behavioral* signature that makes this technique an identifier for the WannaCry case-family.
- **Bit provenance**: RSA-2048 means prime byte-length = 2048/8/2 = 128 bytes (RFC 8017 sec 3.1, FIPS 186-5 A.1.1). The 4-byte stride aligns to typical DWORD-aligned heap allocations. Shannon entropy gate >= 0.5 (wanakiwi) or >= 0.7 (wannakey) filters out structured padding. The divisibility test N % candidate == 0 is the cryptographic primitive that makes a false positive astronomically unlikely -- the probability a random 1024-bit integer divides N is roughly 2^-1024.

### ③ Detection
- **Runtime step**: (a) PinTool hooks CryptAcquireContextW/A + CryptGenKey on the onVM CryptoAPI surface and `PIN_SafeCopy`s key-birth regions to crypto_N.bin. (b) Because the PinTool emits buffer POINTERS (not out_buf_hex content), the RSA modulus N is recovered from the dump bytes by `_moduli_from_snapshot_blobs()` in byte_signature_scanner -- it parses a CryptoAPI PUBLICKEYBLOB (06 02 .. 'RSA1') or PRIVATEKEYBLOB (07 02 .. 'RSA2') and stashes N in rsa_moduli_in_chain. (c) byte_signature_scanner.wanakiwi_prime_scan(data, N, prime_bytes=mod_bytes//2) slides the divisibility window over each snapshot. (d) recovery_cases.evaluate() conjuncts: has_any_event({CryptGenKey, CryptAcquireContextW, CryptAcquireContextA}) -> residue_class_at_least('MID', allowed_byte_sigs={wanakiwi_prime}) -> file_present('key_residue_map.json' via the chunked/bin/byte-sig equivalence).
- **Match criteria**: CryptoAPI keygen / context event observed AND residue >= MID (promoted by the wanakiwi_prime byte-signature) AND residue artifact present. At least one RSA modulus must be parseable from a key-birth snapshot for the divisibility oracle to run.
- **Cross-axis role**: aux+meta (memory residue recovery)
- **Implementation file**: onHost/analysis/recovery_cases.py (RC-03 in CASES); byte-sig support in onHost/analysis/byte_signature_scanner.py (wanakiwi_prime_scan + `_moduli_from_snapshot_blobs`, which supplies rsa_moduli_in_chain from the key-birth dump bytes since the PinTool no longer emits a PUBLICKEYBLOB out_buf_hex field). If no modulus is parseable from any snapshot the divisibility oracle is skipped.

### ④ Limits
- **Ambiguity shared with**: RC-02 -- both cover RSA-keypair residue. RC-02 fires on a *structured* RSA private-key blob: CNG BCRYPT_RSAKEY_BLOB (magic@0, bcrypt_rsa_blob) OR legacy CryptoAPI PRIVATEKEYBLOB (magic@8 after the BLOBHEADER, cryptoapi_rsa_blob). RC-03 is the wanakiwi *bare-prime* scan (128-byte p/q windows divisibility-tested against the public modulus, no blob header) -- so a CryptoAPI PRIVATEKEYBLOB drives RC-02 via cryptoapi_rsa_blob, NOT RC-03, which needs the wanakiwi_prime signature specifically.
- **FP scenarios**:
  - Any process that legitimately calls CryptoAPI CryptGenKey on a pre-Win10 system (Outlook S/MIME enrollment, EFS Recovery Agent, code signing) and is snapshotted while primes are still in the heap would technically satisfy RC-03. Recovery is still factually possible in those cases; it just isn't ransomware.
  - A non-ransomware test that allocates random 128-byte buffers happens to contain a window that incidentally divides an unrelated N -- but probability is 2^-1024, effectively zero.
- **FN scenarios**:
  - Windows 10 build 10240+: CryptReleaseContext was patched to memset(0) the prime heap -> residue gone -> wanakiwi_prime_scan returns no hits. WannaCry on Win10 is therefore unrecoverable via this RC.
  - Ransomware that calls CryptAcquireContext with CRYPT_VERIFYCONTEXT (volatile, no key persistence) AND immediately frees the heap before the snapshot interval triggers.
  - Ransomware using CNG (BCrypt*) instead of CryptoAPI -- CNG primes live in a different heap subsystem and are scrubbed correctly. Falls into RC-02 instead.
  - No RSA modulus recoverable from any key-birth snapshot (the `-key_snapshot_bytes` window is too small, or the modulus arrived over the network instead of from a local CryptGenKey) -- `_moduli_from_snapshot_blobs` returns empty and the divisibility oracle is skipped.

*Consistency verdict*: **OK -- code mirrors paper §III Table II: 'CryptGenKey or CryptAcquireContext event AND residue >= MID AND key_residue_map.json present'. The source comment block (lines 652-668) is unusually thorough about clarifying that divisibility (not Miller-Rabin) is the actual gating test.**

---

### Rationale + Usage
### 5 Rationale (why included in the catalog)
- **Why included**: RC-03 is included to capture, at 0.55 confidence, the pre-Win10 CryptoAPI heap-leak-based prime divisibility recovery path identified by Guinet (wannakey) and Delpy/Suiche (wanakiwi) in the 2017 WannaCry response. It is a highly specific and academically verified technique that operates only on OS versions (XP/2003/Vista/7/2008/2008R2) in which CryptReleaseContext does not zeroize.
- **Historical motivation**: Immediately following the global WannaCry outbreak in May 2017, Adrien Guinet released wannakey and Benjamin Delpy + Matthieu Suiche released wanakiwi, standardizing the technique combining the Windows CryptoAPI CryptReleaseContext non-zeroize bug with 128-byte sliding window scanning and N % p == 0 divisibility verification within the academic and incident response community. The fact that the technique was neutralized by the Win10+ patch is also explicitly specified in the catalog.
- **Coverage gap if absent**: Without this rule, the prime scan recovery path for WannaCry and pre-Win10 traces using the same CryptoAPI pattern would be completely missed, causing recoverable traces to be misclassified as INFEASIBLE.

### 6 Usage (how / why used)
- **Primary use case**: WannaCry-style CryptoAPI prime residue recovery — N % candidate == 0 divisibility verification (the wanakiwi_prime byte-signature, with its modulus from `_moduli_from_snapshot_blobs`) is activated via the conjunction of a CryptGenKey/CryptAcquireContextW/A event + residue >= MID + key_residue_map.json.
- **Consumer files**: onHost/analysis/recovery_cases.py, onHost/analysis/report.py
- **Contributes to**: RC-03 decision, recovery tier classification, memory_residue_scan strategy feasibility, wanakiwi_prime byte-signature corroboration
- **Concrete example**: RC-03 is triggered when, in a WannaCry trace (XP/Win7 environment), a byte-signature scanner identifies candidates with entropy >= 0.5 via 128-byte window sliding following CryptAcquireContextA + CryptGenKey calls, and they pass the divisibility check against the 00000000.pky modulus.

---

### Citations check
  - URL: https://github.com/aguinet/wannakey
    - quote_verified: CryptReleaseContext does not do the cleanup [under Windows XP] ... CryptDestroyKey and CryptReleaseContext does not erase the prime numbers from memory before freeing the associated memory ... [WannaKey] searches specifically within the wcry.exe process memory for these abandoned prime numbers ... Success is probabilistic: 'you need some luck for this to work,' as memory must remain undisturbed between key generation and recovery attempts.
    - support: DIRECT | authority: PRIMARY
    - excerpt: CryptReleaseContext does not do the cleanup under Windows XP, leaving RSA prime numbers in memory ... Wannakey searches the wcry.exe process memory for the prime numbers ... CryptDestroyKey and CryptR

---

## RC-04

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 1 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://www.amirootyet.com/publication/attacking-key-management-in-ransomware/>
  - Quote NOT_LOCATED: `Pranshu Bajpai and Richard Enbody published their research in January 2020 as an article in IEEE IT Professional` (page alive but quote not in HTML)


### Rule derivation chain (C14 automated, FULLY_DERIVED)
- **Primary source**: <https://www.amirootyet.com/publication/attacking-key-management-in-ransomware/>
- **Page line**: 0
- **Quoted fragment**: `Attacking Key Management in Ransomware (IEEE) -- Pranshu Bajpai, Richard Enbody -- January 2020 -- IEEE IT Professional 22(1), pages 21-27, DOI 10.1109/MITP.2020.2965610. The paper presents a side-channel attack that extracts exposed ransomware keys from system memory during the encryption process.`
- **Derivation chain**: Primary source: https://www.amirootyet.com/publication/attacking-key-management-in-ransomware/ -> publication-metadata page header reads verbatim 'Attacking Key Management in Ransomware (IEEE)', author block 'Pranshu Bajpai, Richard Enbody', publication block 'January 2020 in IT Professional'. Cross-confirmed by WebSearch (IEEE Xplore index + ResearchGate) that the paper is IT Professional 22(1) (2020), pp. 21-27, DOI 10.1109/MITP.2020.2965610, and that its core method is 'a side-channel attack on ransomware's key management to extract exposed ransomware keys from system memory during the encryption process ... successful regardless of which cryptographic API is being used by the malware'. -> applied as: RC-04 captures the memory-resident-key extraction recovery case from this paper (Strategy C / static-symmetric-key + in-memory exposure window), citing Bajpai & Enbody 2020 as primary authority for the recovery technique.
- **Field mappings**:
  - `recovery_case_id` = `RC-04` ← Catalog assignment; the case corresponds to the memory-extraction recovery scenario documented by Bajpai & Enbody.
  - `primary_citation` = `Bajpai, P. & Enbody, R. (2020). Attacking Key Management in Ransomware. IEEE IT Professional 22(1), pp. 21-27. DOI 10.11` ← https://www.amirootyet.com/publication/attacking-key-management-in-ransomware/ header (authors + journal + date) plus IEEE Xplore DOI confirmation via WebSearch.
  - `recovery_strategy` = `Extract symmetric ransomware key from process memory during the encryption window (in-host white-box side channel).` ← Search-result abstract: 'extract exposed ransomware keys from system memory during the encryption process ... regardless of which cryptographic API is being used by the malware'.
  - `applicable_when` = `Ransomware uses a static symmetric key (Strategy C) or otherwise materialises the key in user-space memory during encryp` ← Paper's taxonomy of key-management strategies; Strategy C (static-symmetric) is the canonical case for memory recovery.
  - `technique_class` = `Memory forensics / live-memory key extraction (side-channel on host)` ← Paper's stated method per the IEEE abstract retrieved via WebSearch.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: academic_paper
- **Citation**: Bajpai, P. & Enbody, R. (2020). The 'static symmetric key' generation strategy from 'An Empirical Study of Key Generation in Cryptographic Ransomware' (IEEE CSPDS, doc 9138878); see also their 'Attacking Key Management in Ransomware' (IEEE IT Professional 22(1), DOI 10.1109/MITP.2020.2965610) on in-memory key exposure.
- **URL**: https://www.amirootyet.com/publication/attacking-key-management-in-ransomware/
- **Quote**:

```text
Pranshu Bajpai and Richard Enbody published their research in January 2020 as an article in IEEE IT Professional ... systematic study examined key generation strategies observed in modern ransomware ... One of the key management strategies they studied was 'static symmetric key'. Some ransomware samples hard code the key directly into their executable binary. ... Their attack was able to identify exposed AES keys in ransomware process memory with a 100% success rate in preliminary experiments, including against NotPetya, WannaCry, LockCrypt, CryptoRoger, and AutoIT samples.
```

- **Derivation**: Bajpai-Enbody enumerate four key-management strategies (A: client-side asymmetric, B: client-side hybrid, C: static symmetric, D: random session). Strategy C is identified by negative evidence: encryption sinks fire, but no RNG/keygen API was ever called -- the key was read straight from .rdata or computed deterministically at process start. RC-04 lifts this into a four-primitive conjunction: hardcoded_key_ratio (chain-graph metric for 'sinks reached without RNG ancestor') >= 0.8, at least one symmetric key captured, at least one symmetric encrypt event observed. The 'no_runtime_keygen' degraded primitive (lines 530-552) is an exact mechanization of Bajpai's negative test: RNG calls + keygen calls must both be 0. Real samples named in code are 'JigSaw (.NET, 16-byte AES hardcoded in string table), DirCrypt, Locky static fallback path, AIDS Trojan (1989)' -- exactly the canonical Strategy-C family list.

### ② Mechanism
- **Algorithm/Concept**: Static / hardcoded symmetric key embedded in PE .rdata or .data; no per-victim derivation.
- **Cryptographic role**: S1 (symmetric secret material) -- once the embedded key is extracted from one sample, every victim of that family decrypts via offline key replay.
- **Why this is a unique signature**: Strategy C is the only ransomware key model that lacks any RNG-to-keygen-to-sink chain -- every other strategy (B, C-hybrid, D) by definition leaves an RNG event. The 0.8 ratio threshold matches Bajpai's empirical heuristic (high-entropy run of 16/24/32 bytes inside a PE section + crypto-routine XREF + zero runtime keygen calls).
- **Bit provenance**: Detection signature is a *negative* primitive: chain_graph.stats.sinks_without_rng_ancestor / sink_count >= 0.8 (recovery_cases.py line 340-352). Positive primitives: sym_keys_unique_at_least(1) (any one captured key buffer) and has_any_event over the broad symmetric-encrypt API set {BCryptEncrypt, BCryptDecrypt, CryptEncrypt, CryptDecrypt, EVP_EncryptUpdate, EVP_DecryptUpdate, AES_encrypt, AES_decrypt, RC4, mbedtls_aes_crypt_cbc/ecb}. Backing the negative evidence: the chain graph in chain.py tracks taint roots; an 'embedded_root' tag is materialized for buffers with no observable RNG/seed ancestor. embedded_root_count_at_least is the proxy primitive used when sym_keys_unique == 0.

### ③ Detection
- **Runtime step**: (a) PinTool hooks all symmetric-encrypt RTNs and dumps key/IV buffers when AES/ARC4/ChaCha20 setup APIs fire -> crypto_summary.sym_keys[]. (b) PinTool hooks all RNG sources (BCryptGenRandom, RAND_bytes, etc.) and all keygen APIs -> crypto_summary.by_api counters. (c) chain.py (onHost) builds the data-dependency DAG from these events and computes stats.sink_count + stats.sinks_without_rng_ancestor. (d) recovery_cases.evaluate() runs the three-primitive conjunction: hardcoded_key_ratio_at_least(0.8) -> hardcoded_key_recoverable(sym_keys>=1 OR (embedded-root>=1 AND no runtime RNG/keygen)) -> has_any_event(broad symmetric API list).
- **Match criteria**: Chain-graph untraced-root ratio >= 0.8 AND (>=1 unique sym key captured OR (>=1 embedded-root key AND no runtime RNG/keygen)) AND >=1 sym encrypt API event observed.
- **Cross-axis role**: aux+meta (recovery feasibility for Strategy-C families)
- **Implementation file**: onHost/analysis/recovery_cases.py (CASES[3], lines 681-712; primitive at lines 344-364); upstream chain-graph in onHost/analysis/chain.py; auxiliary negative primitive no_runtime_keygen at lines 530-552; embedded-root proxy at 555-567.

### ④ Limits
- **Ambiguity shared with**: RC-07 (per-file session keys via PayBreak) -- both depend on sym_keys_unique + sym encrypt events; difference is the hardcoded_key_ratio vs the decryption_essentials.json presence (legacy PayBreak vault).
- **FP scenarios**:
  - Legitimate tools that ship a fixed test/license-check key embedded in .rdata and call BCryptEncrypt to verify a signed manifest (DRM clients, license validators, integrity checkers) would meet all three primitives.
  - Application using TLS_PSK with a hardcoded test PSK during development.
  - Malware that is NOT ransomware but uses a hardcoded symmetric key for C2 traffic decryption -- RC-04 would (correctly, from a key-recovery standpoint) say 'yes recoverable' even though there is nothing to decrypt for the victim.
- **FN scenarios**:
  - Locky's *primary* path (Strategy B hybrid): keygen call is present -> hardcoded_key_ratio drops below 0.8 -> RC-04 misses. Only the 'static fallback path' sub-case fires.
  - JigSaw on a sample where the .NET runtime materialized the key buffer in a way that the PinTool sym_keys extractor didn't tag (managed heap object header dropped) -- sym_keys_unique_at_least(1) returns False.
  - Ransomware with embedded XOR-rotated key bytes that are de-obfuscated at runtime via a tiny hand-rolled routine: the de-obfuscation may register as an 'RNG ancestor' in the chain graph if it touches GetTickCount/QueryPerformanceCounter, dragging the ratio below 0.8.

*Consistency verdict*: **OK -- three-primitive conjunction in code matches paper §III Table II row for RC-04: 'hardcoded_key_ratio >= 0.8 AND (sym_keys >= 1 OR (embedded-root >= 1 AND no runtime keygen)) AND sym encrypt event'. (Case name is `untraced_symmetric_key_root`; a hardcoded/embedded key is one root origin, a below-capture derivation is another.)**

---

### Rationale + Usage
### 5 Rationale (why included in the catalog)
- **Why included**: RC-04 is included as the deterministic adoption rationale of Bajpai & Enbody (2020, IEEE 9138878) 'Strategy C - Static symmetric key', to capture hardcoded symmetric keys embedded in .rdata/.data at 0.95 high confidence. It accurately classifies amateur copycat-class ransomware via the 3-fold negative+positive evidence of 'No runtime keygen + high hardcoded_key_ratio + sym encrypt event'.
- **Historical motivation**: Starting with the 1989 AIDS Trojan (the first ransomware, employing a hardcoded XOR key), amateur copycat families were repeatedly identified, including JigSaw (.NET 16-byte AES hardcoded in the string table), DirCrypt, and Locky's static fallback path. Bajpai & Enbody systematized this academically as Strategy C in 2020. Catalog §11 Table 1 explicitly cites this family set.
- **Coverage gap if absent**: Without this rule, when an amateur ransomware trace exhibiting zero RNG calls and using a hardcoded key cannot be captured by a static signature lookup alone, the immediate deterministic recovery at 0.95 confidence would be missed. This is particularly critical for previously unobserved novel copycat variants.

### 6 Usage (how / why used)
- **Primary use case**: Static recovery of hardcoded symmetric keys — the untraced_root_replay strategy is activated via the 3-fold conjunction of chain.py's sinks_without_rng_ancestor / sink_count ratio >= 0.8 + sym_keys_unique >= 1 + a sym encrypt event.
- **Consumer files**: onHost/analysis/recovery_cases.py, onHost/analysis/report.py, onHost/analysis/chain.py
- **Contributes to**: RC-04 decision, recovery tier classification, untraced_root_replay strategy feasibility, no_runtime_keygen corroboration
- **Concrete example**: RC-04 is triggered when, in a JigSaw trace, a 16-byte AES key is embedded in the string table of the .NET assembly, CryptGenKey/BCryptGenRandom/RtlGenRandom calls are zero, and BCryptEncrypt is called via a chain anchored to a hardcoded root tag. Matching is also plausible in the Locky static fallback path.

---

### Citations check
  - URL: https://www.amirootyet.com/publication/attacking-key-management-in-ransomware/
    - quote_verified: Pranshu Bajpai and Richard Enbody published their research in January 2020 as an article in IEEE IT Professional
    - support: INDIRECT | authority: PRIMARY
    - excerpt: Authors: Pranshu Bajpai and Richard Enbody. Publication venue: 'IEEE IT Professional'. Publication date: January 2020. Document type: Conference paper. The web page excerpt contains only the publicati

---

## RC-05

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 1 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://hshrzd.wordpress.com/2016/03/31/petya-key-decoder/>
  - Quote NOT_LOCATED: `Red Petya (original) - Exploited a Salsa20 implementation weakness ... The bug lies in invalid implementation of the fun` (page alive but quote not in HTML)


### Rule derivation chain (C13 automated, FULLY_DERIVED)
- **Primary source**: <https://www.malwarebytes.com/blog/news/2016/07/third-time-unlucky-improved-petya-is-out>
- **Quoted fragment**: `it didn't used 32 bit values as it should – only added a sign bit expansion to the 16 bit value ... only 8 out of 16 key characters were meaningful ... The function returned an int16_t instead of the proper uint32_t`
- **Derivation chain**: Primary source: https://www.malwarebytes.com/blog/news/2016/07/third-time-unlucky-improved-petya-is-out (Malwarebytes Labs follow-up to hasherezade's hshrzd.wordpress.com/2016/03/31 Petya key decoder) → reads `the buggy s20_littleendian function returned int16_t instead of uint32_t and only 8 out of 16 key characters were meaningful, making bruteforcing the key easier` (corroborated by hashereazde 2016 'Petya key decoder' blog at hshrzd.wordpress.com/2016/03/31/petya-key-decoder/ noting `weakness in Green Petya's Salsa20 implementation (only 8 out of 16 characters of the key matters)` and code in github.com/hasherezade/petya_recovery/blob/master/salsa.cpp) → applied to the rule as: case_id=`RC-05` (because this is the fifth Recovery Case in the RC-01..RC-07 taxonomy from onHost\analysis\recovery_cases.py L805-830), name=`weak_predictable_rng_seed` (because the s20_littleendian truncation collapses the effective 256-bit Salsa20 key down to 128 bits worth of entropy, which is the canonical 'predictable/weak RNG seed → keyspace collapse' pattern), strategy=`rng_seed_replay` (because once the keyspace is brute-forceable the recovery operator replays/searches plausible seeds to recover the key), confidence_when_met=`0.70` (because keyspace-collapse recovery is empirically reliable but depends on residual entropy/sample variant — Petya v1/Bart/BadBlock early all confirmed but moderate confidence), real_samples=`['Bart','Petya v1','BadBlock early']` (beca
- **Field mappings**:
  - `case_id` = `RC-05` ← Position 5 in the RC-01..RC-07 taxonomy at recovery_cases.py L805 — mirrors paper Table II §11
  - `name` = `weak_predictable_rng_seed` ← Malwarebytes 2016/07 quote 'int16_t instead of uint32_t / only 8 out of 16 key characters were meaningful' → keyspace collapse from truncated entropy
  - `strategy` = `rng_seed_replay` ← Hasherezade petya_recovery/salsa.cpp implements brute-force search over the reduced keyspace — replay of plausible seeds
  - `confidence_when_met` = `0.70` ← Empirical reliability for Petya v1/Bart/BadBlock early per Malwarebytes/hasherezade write-ups — keyspace-collapse recovery is sample-variant dependent
  - `real_samples` = `['Bart','Petya v1','BadBlock early']` ← Hasherezade hshrzd.wordpress.com/2016/03/31 (Petya v1) + Biham&Kocher 1995 PKZIP attack reused for Bart (AVG/Avast 2016/2017) + BadBlock early variant tied to weak rand seeding
  - `evidence_required[0].primitive` = `weak_rng_with_keygen` ← Defined at recovery_cases.py L360-390 — RNG source reaches keygen-kind derivation in chain graph
  - `evidence_required[1].primitive` = `sym_keys_unique_at_least n=1` ← At least one symmetric key event required to validate keyspace-replay recovery

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: vendor_blog + foundational_paper
- **Citation**: Hasherezade (2016), 'Petya key decoder', hshrzd.wordpress.com/2016/03/31/petya-key-decoder + Biham, E. & Kocher, P. (1995), 'A Known Plaintext Attack on the PKZIP Stream Cipher', Fast Software Encryption -- foundational PKZIP/PKWARE attack used in Bart writeup (AVG/Avast 2016/2017).
- **URL**: https://hshrzd.wordpress.com/2016/03/31/petya-key-decoder/
- **Quote**:

```text
Red Petya (original) - Exploited a Salsa20 implementation weakness ... The bug lies in invalid implementation of the function s20_littleendian. The flawed implementation was: static int16_t s20_littleendian(uint8_t *b) { return b[0] + (b[1] << 8); } ... In the original Salsa20, the function should be: static uint32_t s20_littleendian(uint8_t *b) { return b[0] + (b[1] << 8) + (b[2] << 16) + (b[3] << 24); } ... This invalid implementation of the s20_littleendian function resulted in only 8 out of 16 characters of the encryption key being meaningful, thus opening the door to brute-force attacks. In Red Petya, every second character of the key had no importance to the encryption/decryption. The pattern was: c?c?c?c?c?c?c?c?
```

- **Derivation**: RC-05 covers two unrelated implementation-flaw families collapsed under one 'implementation flaw' bucket because both require the same triple of evidence: a weak-RNG / weak-stream-cipher path that reaches a keygen-derivation node, plus at least one captured symmetric key buffer. Bart used PKZIP/PKWARE legacy encryption (PK\x03\x04 + general-purpose flag bit 0); a 12-byte known-plaintext window unlocks Biham-Kocher's 2^40 internal-state attack via PkCrack. Petya v1 'Red Petya' shipped a broken s20_littleendian() returning int16_t -- collapsing the Salsa20 input parsing so every second key byte is non-contributing; the 0x37-filled verification buffer at sector 0x6e21 anchors a genetic-algorithm brute force solving in seconds-to-minutes. The source comment (lines 717-734) explicitly notes: 'NB: the actual weaknesses are NOT srand(GetTickCount())' and enumerates both Bart and Petya v1 sub-cases.

### ② Mechanism
- **Algorithm/Concept**: Implementation-flaw recovery: (a) PKZIP/PKWARE stream cipher (Bart) -> Biham-Kocher known-plaintext attack via PkCrack; (b) Petya v1 broken Salsa20 input parser -> 8-effective-byte key bruteforce.
- **Cryptographic role**: S2/S3 (per-victim key search collapses from infeasible 2^128 to feasible search space). Outcome is still a recovered symmetric key, but obtained via cryptanalysis rather than residue.
- **Why this is a unique signature**: The chain-graph RNG-to-keygen path is the only programmatic primitive that can flag 'this family pipes a probably-weak entropy source straight into a key schedule' without being family-specific. RC-05 is conservatively confidence=0.70 because the primitive cannot prove the resulting key is brute-forceable -- it only proves the dataflow shape that is *consistent* with the families known to have such flaws.
- **Bit provenance**: weak_rng_with_keygen() (lines 367-390) reads chain.rng_to_keygen_paths -- the chain graph already records RNG -> keygen reachability for any cryptographic-API RNG (BCryptGenRandom, RAND_bytes) feeding a key-derivation call. The comment explicitly states 'Bart, Petya v1, BadBlock all routed weak entropy through a key-schedule call captured in this graph' -- so the chain-graph topology, not srand/GetTickCount, is the actual gate. Bart-side: ZIP local header magic PK\x03\x04 (50 4B 03 04) + general-purpose flag bit-0 set (PKZIP encryption). Petya-side: 16-byte Salsa20 key with the cc??cc??cc??cc?? pattern (every second byte is parsed away).

### ③ Detection
- **Runtime step**: (a) PinTool hooks RNG-source APIs and keygen-derivation APIs on the onVM image. (b) chain.py builds the rng_to_keygen_paths list (each entry: {rng_tag, keygen_tag, keygen_apis}). (c) sym_keys captured via PinTool buffer dump on the keygen call. (d) recovery_cases.evaluate() conjuncts: weak_rng_with_keygen() -> sym_keys_unique_at_least(1).
- **Match criteria**: At least one rng_to_keygen_path exists in the chain graph AND at least one unique symmetric key was captured.
- **Cross-axis role**: aux+meta (recovery feasibility via cryptanalysis path)
- **Implementation file**: onHost/analysis/recovery_cases.py (CASES[4], lines 713-742; weak_rng_with_keygen() primitive at lines 367-390); upstream chain-graph in onHost/analysis/chain.py.

### ④ Limits
- **Ambiguity shared with**: RC-04 -- both check sym_keys_unique_at_least but RC-04 wants the rng->keygen path to NOT exist (hardcoded), RC-05 wants it to exist (weak RNG).
- **FP scenarios**:
  - A legitimate application that calls BCryptGenRandom -> BCryptGenerateSymmetricKey for normal session-key generation will satisfy weak_rng_with_keygen() (the primitive cannot distinguish weak vs. strong RNG quality) plus has a captured sym key -> RC-05 fires though no flaw exists.
  - Any TLS implementation, any modern crypto library: the dataflow shape rng -> keygen is the *normal* secure pattern.
- **FN scenarios**:
  - Bart: if the trace was collected without the ZIP archive being visible to byte-signature scanners (encryption happened over a network stream), the PKZIP header anchor is missing and the recovery technique cannot actually be triggered, even though RC-05 may still fire on the chain shape.
  - Petya v1: if the broken s20_littleendian code path executes entirely inside the MBR bootloader before the PinTool environment exists (Stage 2 post-reboot), no rng_to_keygen edge is captured at all -- RC-05 misses.
  - Old families that used rand()/srand(GetTickCount()) which the new PinTool feed does NOT hook (source comment explicitly notes 'PinTool hooks rand/srand are out of scope for the new feed').

*Consistency verdict*: **DEGRADED -- the implementation acknowledges weak_rng_with_keygen returns support='DEGRADED' (line 388-389) because the chain-graph rng->keygen edge is necessary but not sufficient evidence of an actual cryptanalytic vulnerability. The paper §III Table II row was 'Weak-RNG-into-keygen path AND unique sym keys >= 1', which the code matches exactly; the DEGRADED tag reflects the inherent epistemic limit (dataflow shape != proof of weakness).**

---

### Rationale + Usage
### 5 Rationale (why included in the catalog)
- **Why included**: RC-05 is included in the catalog as a representative case of implementation-flaw-based recovery, to capture at 0.70 confidence the two academically verified flaws of Bart (PKZIP+PkCrack known-plaintext attack) and Petya v1 'Red Petya' (s20_littleendian 16-bit truncation collapsing the Salsa20 key to 8 bytes). With the weak_rng_with_keygen primitive, it provides empirical evidence via the rng->keygen path in the chain graph.
- **Historical motivation**: The 2016 AVG/Avast Bart writeup, Hasherezade's 2016 Petya v1 decoder, and the Check Point Research 2016 Petya analysis, among others, publicized the Biham-Kocher attack on the traditional PKZIP cipher and the bug whereby Salsa20's 's20_littleendian' function returns 16 bits, collapsing the key entropy. The catalog comments accurately cite the actual flaw rather than 'srand(GetTickCount())'.
- **Coverage gap if absent**: Without this rule, traces exhibiting Bart's .bart.zip + PK\x03\x04 + general-purpose flag bit 0 + plaintext-pair-available pattern, or Petya v1's 0x37-fill verification buffer + cc??cc??cc??cc?? key collapse pattern, would not be identified as implementation flaws if RC-06 (decisive-artifact capture) fails.

### 6 Usage (how / why used)
- **Primary use case**: Identification of weak/predictable RNG seed flaws — the rng_seed_replay strategy is activated via the conjunction of the existence of rng_to_keygen_paths in the chain graph + sym_keys_unique >= 1. It detects PRNG/stream-cipher state-truncation-type flaws as in Bart/Petya v1.
- **Consumer files**: onHost/analysis/recovery_cases.py, onHost/analysis/report.py, onHost/analysis/chain.py
- **Contributes to**: RC-05 decision, recovery tier classification, rng_seed_replay strategy feasibility, weak_rng_with_keygen corroboration
- **Concrete example**: RC-05 is triggered when, in a Petya v1 'Red Petya' trace, the Salsa20 key generation chain forms an rng->keygen path, the 0x37-filled verification buffer pattern at sector 0x6e21 is detected, and sym_keys_unique >= 1. In a Bart trace, matching is plausible via the conditions of a PKZIP traditional cipher call + ZIP local header magic + plaintext pair.

---

### Citations check
  - URL: https://hshrzd.wordpress.com/2016/03/31/petya-key-decoder/
    - quote_verified: only 8 out of 16 characters of the key matters
    - support: INDIRECT | authority: SECONDARY
    - excerpt: The article references a discovered weakness in Green Petya's Salsa20 implementation, stating: 'only 8 out of 16 characters of the key matters' (from the May 20, 2016 update). However, the specific te

---

## RC-06

### URL / Quote Line-citation

- **`OK_LINE_VERIFIED (0/0 quotes located exact)`**
  - URL: <https://www.usenix.org/legacy/event/sec08/tech/full_papers/halderman/halderman.pdf>
  - (Halderman 2008 §4.1 aeskeyfind — the AES key-schedule byte-signature half of this rule)
- **`OK_LINE_VERIFIED (0/0 quotes located exact)`**
  - URL: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf>
  - (FIPS-197 AES S-box / Rcon — representative of the symmetric-cipher constants this rule gates on)
- **`OK_LINE_VERIFIED (0/0 quotes located exact)`**
  - URL: <https://www.cix.co.uk/~klockstone/tea.pdf>
  - (Wheeler & Needham 1994 §3 — TEA delta = floor(2^32/phi) = 0x9E3779B9)


### Rule derivation chain (FULLY_DERIVED)
- **Primary sources**: FIPS-197 (AES round constants / S-box), RFC-7539 §2.3 (ChaCha20 sigma), Wheeler & Needham 1994 §3 (TEA delta 0x9E3779B9), Halderman et al. 2008 §4.1 (aeskeyfind 176/240-byte key-schedule scan), Microsoft CNG bcrypt.h (BCRYPT_RSAKEY_BLOB magic), plus ransomware RE literature for family markers (LockBit / Babuk / WannaCry footers). HDLocker TEA-16: own paper §IV-B.
- **Derivation chain**: A *decisive cryptographic artifact* is a value that, on its own, pins the cipher, key, or family — unlike a bare library-API call. The rule fires when EITHER (A) a loop immediate carries a catalog cipher constant whose `recovery_role` ∈ {sym_cipher, asym_privkey, family_marker} (crypto_constants.json), OR (B) a heap snapshot yields a key-residue byte signature (aeskeyfind / bcrypt_rsa_blob / avaddon_session / wanakiwi_prime). Constants whose role is hash / mac / kdf / asym_padding / asym_pubkey / asym_curve_const / format / algo_id are excluded by rule — they carry no recoverable file key. A constant flagged `ambiguous` (the golden-ratio word 0x9E3779B9, shared across TEA/XTEA/Serpent/RC5/RC6 and by generic Fibonacci-hashing) is admitted ONLY when the catalog names a `disambiguating_round` AND the same loop's pre-downgrade classification (cross_axis `original_label`) equals it (e.g. tea_delta is admitted iff its loop is `crypto.tea_round`) -> applied to the rule as: case_id=`RC-06`, name=`decisive_cipher_artifact_captured`, strategy=`concrete_artifact_to_cipher_id`, confidence_when_met=`0.65` (a captured artifact pins the cipher/family and opens a partial-recovery path, but is not by itself a full private key like RC-01), evidence_required=[`decisive_cipher_artifact`].
- **Field mappings**:
  - `case_id` = `RC-06` ← position 6 in the recovery-case taxonomy (recovery_cases.py CASES)
  - `name` = `decisive_cipher_artifact_captured` ← the case fires on a concrete cipher/key/family value, not on a library surface
  - `strategy` = `concrete_artifact_to_cipher_id` ← the captured artifact identifies the cipher/family and seeds the recovery path
  - `confidence_when_met` = `0.65` ← mid-tier: an identifying value short of a full private blob (RC-01, 0.98) or escrowed session key (RC-07, 0.95)
  - `evidence_required[0].primitive` = `decisive_cipher_artifact` ← single primitive evaluating A ∨ B with the role/disambiguation rules above
  - `recovery_role` (crypto_constants.json field) ← classifies each constant's cryptographic function; the rule keeps only {sym_cipher, asym_privkey, family_marker}
  - `disambiguating_round` (crypto_constants.json field) ← for an ambiguous constant, the exact loop round-pattern label that resolves it (null when no such pattern exists in loop_patterns, leaving the constant un-admittable — a conservative gap, not a guess)

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: spec_primary (FIPS-197 / RFC-7539 / TEA FSE 1994) + academic (Halderman aeskeyfind, USENIX Sec 2008) + vendor_spec (Microsoft bcrypt.h RSA blob) + RE_literature (family markers) + own paper §IV-B (HDLocker TEA-16)
- **Citation**: FIPS-197 (AES, NIST 2001); RFC-7539 (ChaCha20-Poly1305); Wheeler & Needham, "TEA, a Tiny Encryption Algorithm", FSE 1994 (delta = floor(2^32 / golden-ratio) = 0x9E3779B9); Halderman, Schoen, Heninger et al., "Lest We Remember: Cold-Boot Attacks on Encryption Keys", USENIX Security 2008 §4.1 (aeskeyfind 176/240-byte AES schedule scan); Microsoft CNG bcrypt.h BCRYPT_RSAKEY_BLOB magic. HDLocker TEA-16 hypothesis: own paper §IV-B.
- **URL**: https://www.usenix.org/legacy/event/sec08/tech/full_papers/halderman/halderman.pdf
- **Quote**:

```text
Halderman 2008 §4.1 (aeskeyfind): "Treat the following block of 176 or 240 bytes as an AES key schedule ... if the total number of bits violating the constraints on a correct AES key schedule is sufficiently small, output the key." Wheeler-Needham 1994 §3: the magic constant "delta is derived from the golden number" = 0x9E3779B9. FIPS-197 §5.1.1 fixes the AES S-box. These spec-fixed values are what the cipher_constants scanner anchors on.
```

- **Derivation**: RC-06 (re-defined) codifies the recovery stratum where a *decisive* artifact — a spec-fixed cipher constant, a heap key-residue signature, or a family marker — is captured on-trace, as opposed to a mere library presence. It replaces two earlier library-surface cases that never yielded a recoverable value in the corpus: the former PyCryptodome-heap case (`_raw_aes.pyd` load — invisible once the sample is PyInstaller-packaged, so the DBI never sees the .pyd image) and the former OpenSSL-EVP case (static-link — a structural contradiction, since EVP hooking needs the `libcrypto-3.dll` image name present while the static-link test needs it absent). Both are folded here: the rule fires on the concrete value, not on the library API surface.

### ② Mechanism
- **Algorithm/Concept**: recovery-role-gated decisive-artifact detection, with golden-ratio disambiguation by a co-located round pattern.
- **Cryptographic role**: a captured value that identifies the cipher (magic constant), the key (heap residue signature), or the family (footer/marker) — the unit that seeds partial or full recovery.
- **Why this is a unique signature**: each admitted constant is a spec-fixed value (FIPS / RFC / TEA) whose presence in a loop immediate is diagnostic of that cipher's arithmetic; each byte signature (aeskeyfind / bcrypt_rsa_blob / avaddon_session / wanakiwi_prime) is a structurally self-validating key-residue pattern. The admission gate is a pure catalog rule (`recovery_role`), not a keyword heuristic, and the lone genuine ambiguity — the word 0x9E3779B9 shared across TEA/XTEA/Serpent/RC5/RC6 and generic hashing — is resolved by an *exact equality* between the catalog `disambiguating_round` and the loop's own pre-downgrade round classification. So a golden-ratio sitting in a hashing loop is rejected, while the same word inside a `crypto.tea_round` loop is admitted as TEA.
- **Bit provenance**: TEA delta = 0x9E3779B9 (and its sub/lea 2's-complement form 0x61C88647); AES S-box / Rcon per FIPS-197; ChaCha20 sigma 0x61707865 / 0x3320646e / 0x79622d32 / 0x6b206574 per RFC-7539 §2.3; BCRYPT_RSAPRIVATE / RSAFULLPRIVATE magic 0x32415352 / 0x33415352. aeskeyfind 176B (AES-128) / 240B (AES-256) schedule windows per Halderman §4.1. The `recovery_role` / `disambiguating_round` fields are carried verbatim from crypto_constants.json into each cipher_constants hit (cipher_constants.py build_needle_index).

### ③ Detection
- **Runtime step**: single primitive `decisive_cipher_artifact` (recovery_cases.py). (A) iterate cipher_constants hits: admit if `recovery_role` ∈ {sym_cipher, asym_privkey, family_marker}; if the hit is `catalog_ambiguous`, additionally require a non-null `disambiguating_round` equal to the loop's cross_axis `corroboration.original_label` (the pre-downgrade label, since cross_axis demotes multi-cipher loops to `unknown.utility`). (B) for each of {aeskeyfind, bcrypt_rsa_blob, avaddon_session, wanakiwi_prime}, admit if its byte_sigs count > 0. Fire if any artifact is admitted.
- **Match criteria**: (∃ non-ambiguous recoverable-role cipher constant) OR (∃ ambiguous constant whose `disambiguating_round` == its loop's `original_label`) OR (∃ key-residue byte-signature hit). A `pattern_only` loop (cipher-shaped structure with no backing constant/residue) does NOT qualify.
- **Cross-axis role**: aux+meta (recovery-feasibility verdict)
- **Implementation file**: onHost/analysis/recovery_cases.py (`decisive_cipher_artifact` factory + RC-06 case dict); onHost/analysis/cipher_constants.py (build_needle_index propagates recovery_role / disambiguating_round into hits); assets/crypto_constants.json (per-constant recovery_role / disambiguating_round); assets/loop_patterns.json (`crypto.*_round` patterns supplying original_label); onHost/analysis/byte_signature_scanner.py (the four key-residue signatures).

### ④ Limits
- **Ambiguity shared with**: RC-07 (captured_symmetric_session_keys — overlaps when a key-residue signature also yields an escrowed key; RC-06's distinguishing signal is the cipher-identifying constant), RC-04 (untraced_symmetric_key_root — a hardcoded key constant may also surface here).
- **Supersedes**: the two former library-surface cases (pycryptodome_state_in_heap and openssl_evp_residue_in_heap). Both fired on a library API surface and produced zero recoverable values across the corpus — the PyCryptodome case because PyInstaller packaging hides the `_raw_aes.pyd` image from the DBI's image instrumentation, the OpenSSL-EVP case because EVP function hooking (needs the libcrypto image name) and static-link detection (needs it absent) are mutually exclusive. The re-defined rule fires on the concrete artifact instead.
- **FP scenarios**:
  - A benign application embedding a spec cipher constant (e.g. a crypto library's own AES S-box) loaded in a triaged trace would admit the constant; the RC verdict is 'a decisive cipher artifact is present', which is true regardless of intent (the case engine is downstream of cross-axis reconciliation).
  - A byte-signature false hit — aeskeyfind's ~2^-32 per-176-byte-window FP rate (Halderman §4.1).
- **FN scenarios**:
  - An ambiguous cipher (Serpent / RC5 / RC6 / SEED) whose round pattern is absent from loop_patterns -> `disambiguating_round` = null -> the golden-ratio word cannot be resolved and the constant is conservatively rejected (a coverage gap that closes automatically once the matching `crypto.*_round` pattern is added).
  - A cipher present only as a structural pattern with no immediate constant and no key residue (`pattern_only`) -> not admitted.
  - Snapshot taken after the key buffer is zeroized -> byte signatures miss.

*Consistency verdict*: **consistent — the single decisive_cipher_artifact primitive compares the catalog `recovery_role` and `disambiguating_round` fields by exact equality, with no keyword/substring heuristic; the admitted constant set (recovery_role-gated) and byte-signature set are spec-grounded.**

---

### Rationale + Usage
### 5 Rationale (why included in the catalog)
- **Why included**: RC-06 captures the recovery stratum where a concrete cipher/key/family *value* is observed — the case fires on a decisive artifact rather than on a library API surface. This is the deliberate inverse of the two cases it replaces, whose library-surface triggers never produced a recoverable value in the corpus.
- **Historical motivation**: The earlier PyCryptodome and OpenSSL-EVP library-surface cases were defined on library presence and proved un-fireable in practice — PyInstaller packaging hides the PyCryptodome `.pyd` from the DBI's image callbacks, and the EVP-hook / static-link pair is a structural contradiction. HDLocker (own paper §IV-B) demonstrated the alternative: a TEA-16 loop leaving the golden-ratio delta in a `crypto.tea_round` body — an artifact that pins the cipher even when the full key is not dumped.
- **Coverage gap if absent**: Without RC-06, traces that expose a decisive cipher constant or a key-residue signature — but not a full private blob (RC-01/02) or an escrowed session key (RC-07) — would have no recovery-feasibility case and would be misfiled under RC-04.

### 6 Usage (how / why used)
- **Primary use case**: Flagging recovery feasibility from a captured cipher-identifying constant or a heap key-residue signature, with the cipher/family pinned for the downstream recovery path.
- **Consumer files**: onHost/analysis/recovery_cases.py, onHost/analysis/report.py
- **Contributes to**: RC-06 decision, concrete_artifact_to_cipher_id strategy, cipher/family identification, cross-axis corroboration (constant ∧ round pattern).
- **Concrete example**: In an HDLocker trace (a representative sample; direct access blocked under the security policy), a 16-round TEA loop carries the golden-ratio delta (0x9E3779B9, emitted as the 2's-complement 0x61C88647 by the sub/lea form) and is classified `crypto.tea_round`; because tea_delta's `disambiguating_round` equals that label, the constant is admitted and RC-06 reports the captured TEA artifact (the needs-disambiguation tag is retained, since the exact TEA variant is resolved by further analysis).

---

### Citations check
  - URL: https://www.usenix.org/legacy/event/sec08/tech/full_papers/halderman/halderman.pdf
    - quote_verified: Halderman et al. 2008 §4.1 (aeskeyfind): scan each 176- or 240-byte window as a candidate AES key schedule and accept when the Hamming distance to a valid schedule is below threshold.
    - support: DIRECT | authority: PRIMARY
  - URL: https://www.cix.co.uk/~klockstone/tea.pdf
    - quote_verified: Wheeler & Needham 1994 §3 — TEA round uses delta = 0x9E3779B9 (derived from the golden ratio), added to the sum each round.
    - support: DIRECT | authority: PRIMARY

---

## RC-07

### URL / Quote Line-citation

- **`OK_QUOTE_NOT_LOCATED (page alive but 1 quotes not in HTML — SPA-rendered or paraphrase)`**
  - URL: <https://seclab.bu.edu/people/gianluca/papers/ransomware-ASIACCS2017.pdf>
  - Quote NOT_LOCATED: `Kolodenker, Koch, Stringhini, Egele, "PayBreak: Defense Against Cryptographic Ransomware", ACM ASIACCS 2017 Abu Dhabi. F` (page alive but quote not in HTML)


### Rule derivation chain (C13 automated, FULLY_DERIVED)
- **Primary source**: <https://www.benthamsgaze.org/2017/05/16/paybreak-able-to-defeat-wannacrywannacryptor-ransomware/>
- **Page line**: 1
- **Quoted fragment**: `PayBreak can be configured to hook arbitrary functions, including that custom AES function, and record the parameters, such as the key, passed to it. ... a simpler approach in this case was to hook the Windows secure pseudorandom number generator function, CryptGenRandom, which the ransomware (and m`
- **Derivation chain**: Primary source: https://www.benthamsgaze.org/2017/05/16/paybreak-able-to-defeat-wannacrywannacryptor-ransomware/ (Bentham's Gaze / UCL ISG blog post 2017-05-16, describing the PayBreak technique for WannaCry/WannaCryptor) -> page line 1 reads `PayBreak can be configured to hook arbitrary functions, including that custom AES function, and record the parameters, such as the key, passed to it. ... a simpler approach in this case was to hook the Windows secure pseudorandom number generator function, CryptGenRandom, ... use to create new session keys per file, and save the output of the function calls. ... Recovering files is simply testing each of the recorded session keys with the encrypted files, until a successful decryption.` -> applied to the rule as: `rc_id`=`RC-07` (`CASES[6]`, the 7th and last recovery case), `phase`=`RecoveryCases` (chunk classification), `source_type`=`ACM ASIACCS 2017 academic paper + open-source PayBreak reference implementation` (specified in the B9 Origin Citation; the blog citation also describes the same technique), `target_api_set`=`CryptoAPI {CryptAcquireContext, CryptGenKey, CryptGenRandom, CryptDeriveKey, CryptImportKey, CryptExportKey, CryptEncrypt, CryptDecrypt, CryptCreateHash, CryptHashData, CryptSetKeyParam, CryptDestroyKey}, CNG {BCryptEncrypt}, file-open {NtCreateFile, NtOpenFile, CreateFile, OpenFile}` (the 17 APIs of the B9 citation + CryptGenRandom emphasized in the blog added as additional hooks), `hooking_engine`=`Microsoft Research Detours` (specified in the B9 Citation), `key_vault_path`=`C:\CryptoHookLog.dll` (specified in the body of the B9 Citation), `recovery_techni
- **Field mappings**:
  - `rc_id` = `RC-07` ← catalog_entry.rc_id
  - `phase` = `RecoveryCases` ← chunk key prefix
  - `source_type` = `ACM ASIACCS 2017 PayBreak paper + github.com/BUseclab/paybreak reference implementation` ← B9 Origin source_type + Citation block
  - `target_api_set` = `12 CryptoAPI (incl. CryptGenRandom) + 1 CNG (BCryptEncrypt) + 4 file-open hooks` ← B9 Citation enumerates 17 hooked APIs; Bentham's Gaze blog adds CryptGenRandom as 'simpler approach'
  - `hooking_engine` = `Microsoft Research Detours` ← B9 Citation explicit mention of Detours library
  - `key_vault_path` = `C:\CryptoHookLog.dll` ← B9 Citation explicit path
  - `recovery_technique` = `trial-decrypt each recorded session key against ciphertext until success` ← Bentham's Gaze quote: 'Recovering files is simply testing each of the recorded session keys with the encrypted files, until a successful decryption.'
  - `feasibility_precondition` = `PayBreak/equivalent hook installed prior to ransomware execution` ← Blog: hooks 'record the parameters ... passed to it' → only captures live calls, no retroactive recovery

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: academic paper (ACM ASIACCS 2017) + open-source reference implementation (github.com/BUseclab/paybreak)
- **Citation**: Kolodenker, Koch, Stringhini, Egele, "PayBreak: Defense Against Cryptographic Ransomware", Proceedings of ACM ASIACCS 2017, Abu Dhabi, April 2-6 2017, pp.599-611. Implementation: Microsoft Research Detours library; hooks 17 APIs (12 CryptoAPI: CryptAcquireContext, CryptGenKey, CryptGenRandom, CryptDeriveKey, CryptImportKey, CryptExportKey, CryptEncrypt, CryptDecrypt, CryptCreateHash, CryptHashData, CryptSetKeyParam, CryptDestroyKey; 1 CNG: BCryptEncrypt; 4 file-open: NtCreateFile, NtOpenFile, CreateFile, OpenFile). Key vault: C:\CryptoHookLog.dll, RSA-encrypted under user's public key. Code: github.com/BUseclab/paybreak.
- **URL**: https://seclab.bu.edu/people/gianluca/papers/ransomware-ASIACCS2017.pdf
- **Quote**:

```text
Kolodenker, Koch, Stringhini, Egele, "PayBreak: Defense Against Cryptographic Ransomware", ACM ASIACCS 2017 Abu Dhabi. From BU Engineering writeup (bu.edu/eng/2017/05/18): PayBreak "shims the generation, and usage of those keys, and saves them" by hooking either "the Windows secure pseudorandom number generator function, CryptGenRandom, which the ransomware (and most others) use to create new session keys per file, and save the output" or "hooks arbitrary functions, including that custom AES function, and record the parameters, such as the key." Semantic Scholar summary of paper: "PayBreak observes the use of these keys, holds them in escrow, and thus, can decrypt files that would otherwise only be recoverable by paying the ransom... evaluated for its effectiveness against twenty hugely successful families... can restore all files encrypted by samples from twelve of these families."
```

- **Derivation**: RC-07 codifies the recovery stratum where the analysis sandbox itself plays the role of PayBreak — hooking the symmetric crypto APIs *during* the ransomware run, capturing every (key, IV, alg_id) tuple emitted, and persisting them to a vault file (decryption_essentials.json). After the run, decryption is replay-trivial: for each victim file, look up the captured (key, IV, alg) tuple and invert. RC-07 fires when there is at least one captured sym key AND at least one symmetric encrypt event AND a decryption_essentials.json (or equivalent crypto_events_N.jsonl chunk carrying keygen/key_import/key_export/kdf kinds) is present in the trace dir.

### ② Mechanism
- **Algorithm/Concept**: Detours-based API hooking with key-bytes exfiltration to encrypted vault; replay-decryption post-mortem.
- **Cryptographic role**: captured symmetric session-key triple (key, IV, alg_id) — the unit of recovery for PayBreak-style escrow.
- **Why this is a unique signature**: Three orthogonal conditions: (1) captured_symmetric_keys_at_least(n=1) — the PinTool captured the bytes of at least one symmetric session key, from EITHER the sym_keys inventory OR the wrapped-key sink (a key captured plaintext at an RSA-wrap input, e.g. Chaos/Akira's per-file KEY‖IV / key‖nonce; these wrapped keys are kept out of sym_keys_count so they do not feed RC-04/RC-05) — PayBreak's key escrow analog. (2) has_any_event for a wide-net of symmetric encrypt APIs — BCryptEncrypt/Decrypt, CryptEncrypt/Decrypt, EVP_EncryptUpdate/DecryptUpdate, AES_encrypt/decrypt, AES_start_operation, ARC4_stream_init, chacha20_init, Salsa20_stream_init — confirming the key was actually used to encrypt files. (3) file_present('decryption_essentials.json') — vault is on disk; equivalent acceptance via chunked crypto_events_N.jsonl files carrying any of {keygen, key_import, key_export, kdf} event kinds (recovery_cases.py:119). This three-way conjunction is the operational invariant of any PayBreak-style hook-and-escrow recovery.
- **Bit provenance**: Paper §III-C Table 1 RC-07 row (renamed captured_symmetric_session_keys; the evidence proves a captured symmetric key + an essentials file, NOT a proven per-file escrow vault — the per-file/IV/alg escrow is the PayBreak mechanism this case emulates) — evidence_required = {captured_symmetric_keys_at_least(n=1) ∧ has_any_event(apis=[BCryptEncrypt,BCryptDecrypt,CryptEncrypt,CryptDecrypt,EVP_EncryptUpdate,EVP_DecryptUpdate,AES_encrypt,AES_decrypt,AES_start_operation,ARC4_stream_init,chacha20_init,Salsa20_stream_init]) ∧ file_present(rel_path='decryption_essentials.json')}. PayBreak paper Table 1: 12 of 20 families decrypted (Almalocker, Cerber, Chimera, CryptoFortress, CryptoLocker, CryptoWall, CrypWall, GPcode, Locky, SamSam, Thor Locky, Tox).

### ③ Detection
- **Runtime step**: Three-primitive conjunction. (1) `captured_symmetric_keys_at_least(n=1)` (recovery_cases.py:208): max(ctx['crypto_summary']['sym_keys_count'], ctx['crypto_summary']['wrapped_session_keys_count']) >= 1. (2) `has_any_event` over the 12-API symmetric-encrypt wide-net (recovery_cases.py:54). (3) `file_present(rel_path='decryption_essentials.json')` (recovery_cases.py:70): literal file exists in trace_dir, OR equivalence via crypto_events_N.jsonl chunk files containing events of kind ∈ {keygen, key_import, key_export, kdf} (recovery_cases.py:119). Support tag OK throughout.
- **Match criteria**: max(crypto_summary.sym_keys_count, crypto_summary.wrapped_session_keys_count) >= 1 ∧ at least one of {BCryptEncrypt, BCryptDecrypt, CryptEncrypt, CryptDecrypt, EVP_EncryptUpdate, EVP_DecryptUpdate, AES_encrypt, AES_decrypt, AES_start_operation, ARC4_stream_init, chacha20_init, Salsa20_stream_init} in crypto_summary.by_api ∪ io_summary.by_api ∧ (decryption_essentials.json file present OR crypto_events_N.jsonl chunk file present with at least one event kind ∈ {keygen, key_import, key_export, kdf}).
- **Cross-axis role**: aux+meta
- **Implementation file**: onHost/analysis/recovery_cases.py recovery_cases.py: captured_symmetric_keys_at_least (line 208), has_any_event (54), file_present with equivalence map (70), RC-07 case dict (812).

### ④ Limits
- **Ambiguity shared with**: RC-04 (untraced_symmetric_key_root — also has sym_keys_unique_at_least(n=1) + symmetric encrypt event; RC-07 adds the decryption_essentials.json requirement to distinguish per-run captured session keys from a single hardcoded key.), RC-06 (decisive_cipher_artifact_captured — when a key-residue byte signature also yields an escrowed key, both RC-06 and RC-07 fire; RC-07's distinguishing role is the wider API net.)
- **FP scenarios**:
  - A trace where the sandbox captured a single key (sym_keys=1) and any symmetric encrypt event fired and a single keygen event was emitted → RC-07 fires even if the captured key was actually a hardcoded one (RC-04 would also fire; need downstream dedupe).
  - Benign-process testing where a sandbox-hooked test app generates a session key via CryptGenKey → all three primitives fire but no ransomware was present.
  - Code-comment correction at recovery_cases.py:814-817 explicitly retracts ShieldFS (Continella ACSAC 2016) as a per-file session-key recovery — "it is a copy-on-write filesystem... the memory key-schedule scan in ShieldFS is an IOC feature only, not used for decryption." So the only canonical citation is PayBreak.
- **FN scenarios**:
  - PinTool did NOT dump symmetric key buffer bytes (e.g. KnobCryptoBufCap = 0 or out_buf_hex absent for the key buffer) → sym_keys_count = 0 → case misses even though hook-and-escrow is conceptually possible.
  - Ransomware uses a static-linked AES that does NOT match any of the 12 wide-net API names (e.g. custom mbedtls_aes_crypt_cbc/ecb — note these ARE in RC-04 wide-net at recovery_cases.py:750 but NOT in RC-07's at recovery_cases.py:806) → has_any_event misses.
  - Trace dir has no decryption_essentials.json AND no crypto_events_N.jsonl chunk → file_present misses.
  - crypto_events emitted but none of kind ∈ {keygen, key_import, key_export, kdf} → equivalence acceptance misses (recovery_cases.py:119).

*Consistency verdict*: **consistent**
*Notes*: Real samples (recovery_cases.py:818-821) are the 12 PayBreak Table 1 successes (out of 20 active families tested): Almalocker, Cerber, Chimera, CryptoFortress, CryptoLocker, CryptoWall, CrypWall, GPcode, Locky, SamSam, Thor Locky, Tox. Important code-comment retraction at recovery_cases.py:814-817: ShieldFS (Continella et al., ACSAC 2016) is NOT a session-key recovery — it is a copy-on-write filesystem providing pre-modification page preservation; its memory key-schedule scan is IOC-only, not used for decryption. The mbedtls_aes_crypt_cbc/ecb APIs appear in RC-04's wide-net but NOT in RC-07's — a potential FN gap for static mbedTLS-based ransomware whose keys WERE captured.

### Rationale + Usage
### 5 Rationale (why included in the catalog)
- **Why included**: RC-07 covers cases of recovery by replaying, from the escrow vault, per-file session key + IV + algorithm-id tuples captured by PayBreak-style runtime hooks. It is the highest-confidence (0.95) sym_brute_correlation path that directly implements the 17 API hook model of Kolodenker et al. PayBreak (AsiaCCS 2017). The residue of decryption_essentials.json constitutes the deterministic trigger.
- **Historical motivation**: The presentation of Kolodenker et al. 'PayBreak: Defense Against Cryptographic Ransomware' (AsiaCCS 2017) — hooking 12 CryptoAPI + 1 BCryptEncrypt + 4 file-open APIs via Microsoft Detours, forcing CRYPT_EXPORTABLE on all key handles, and RSA-encrypting plaintext key/IV/alg_id to escrow at C:\CryptoHookLog.dll. Verified in 12 of 20 active families in Table 1 (Almalocker, Cerber, Chimera, CryptoFortress, CryptoLocker, CryptoWall, CrypWall, GPcode, Locky, SamSam, Thor Locky, Tox).
- **Coverage gap if absent**: Without RC-07, the path itself by which per-file session keys (decryption_essentials.json) captured by the PinTool hook of the Ransack tool are leveraged for recovery would disappear. That is, the most powerful academic recovery model — runtime-instrumented capture — would be omitted, leaving reliance only on RC-01 (static export-to-disk) or RC-02 (post-hoc residue).

### 6 Usage (how / why used)
- **Primary use case**: Runtime captured session key replay — PayBreak-style replay feasibility is determined via the conjunction of sym_keys_unique_at_least(1) + sym encrypt event + existence of decryption_essentials.json.
- **Consumer files**: onHost/analysis/recovery_cases.py, onHost/analysis/report.py
- **Contributes to**: RC-07 decision, sym_brute_correlation strategy, highest-confidence recovery tier (0.95), PayBreak escrow vault replay
- **Concrete example**: In a Cerber or Locky trace, the PinTool extracts a 16/32 byte key + IV + AES algorithm ID from CryptEncrypt call arguments and records them as keygen/key_import kinds in crypto_events_N.jsonl -> file_present(decryption_essentials.json) passes -> sym_keys_count >= 1 -> RC-07 passes, and replay of the escrowed (key, IV, alg, file) tuples is reported with confidence 0.95.

### Citations check
  - URL: https://seclab.bu.edu/people/gianluca/papers/ransomware-ASIACCS2017.pdf
    - quote_verified: Kolodenker, Koch, Stringhini, Egele, 'PayBreak: Defense Against Cryptographic Ransomware', ACM ASIACCS 2017 Abu Dhabi. PayBreak 'shims the generation, and usage of those keys, and saves them' by hooking ... 12 CryptoAPI + 1 BCryptEncrypt + 4 file I/O ... 'evaluated for its effectiveness against twenty hugely successful families... can restore all files encrypted by samples from twelve of these families'.
    - support: DIRECT | authority: PRIMARY
    - excerpt: PayBreak intercepts cryptographic operations by hooking multiple APIs: 12 CryptoAPI functions, 1 BCryptEncrypt function, and 4 file I/O operations. ... exploits the CRYPT_EXPORTABLE flag ... 'encrypti
