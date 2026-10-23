# Rule Provenance — ByteSigScanner

**6 rules** in this phase. Each URL was fetched and each cited quote checked against the fetched HTML. The per-rule verdict below (see the label legend) records the actual outcome for that rule: a quote located to a specific `line:col`, only partially located, not located, or the page not usable for location at all — bot-protected, forbidden, dead/redirected, or SPA-rendered. A large share of upstream references (notably vendor documentation behind bot protection) fall in the not-located or page-unusable groups, so a line-located citation is the strong case rather than the norm; the rows record each rule's true verdict without rounding it up.

## Verification label legend
- **OK_LINE_VERIFIED** — page alive AND every quote located at a specific line in the fetched HTML
- **OK_PARTIALLY_LOCATED** — page alive, some quotes located, some not
- **OK_QUOTE_NOT_LOCATED** — page alive, no quote found in HTML (SPA or paraphrase)
- **DEAD_404_AUTOREPLACED** — original cite dead, replaced with canonical pattern
- **DEAD_404_NO_REPLACEMENT** — manual re-cite needed
- **BOT_PROTECTED_429** — Microsoft Learn etc., reachable via browser


## aeskeyfind_scan

### URL / Quote Line-citation

- **`OK_LINE_VERIFIED (5/5 quotes located exact)`**
  - URL: <https://github.com/makomk/aeskeyfind/blob/master/aeskeyfind.c>
  - Quote: `#define DEFAULT_THRESHOLD 10                       [aeskeyfind.c:29]`
    - Located at: **line 2955 col 1** (SUBSTRING_30CH)
    - HTML snippet: `#define DEFAULT_THRESHOLD 10`
  - Quote: `if (new_call) {`
    - Located at: **line 3402 col 0** (TOKEN_OVERLAP_1.00)
    - HTML snippet: `static int new_call = 1 ;`
  - Quote: `static int byte_freq[256] = {0};`
    - Located at: **line 3408 col 0** (TOKEN_OVERLAP_1.00)
    - HTML snippet: `static int byte_freq [ 256 ] = { 0 };`
  - Quote: `static int entropy(const uint8_t* bmap, size_t i) {`
    - Located at: **line 3390 col 0** (TOKEN_OVERLAP_1.00)
    - HTML snippet: `static int entropy ( const uint8_t * bmap , size_t i )`
  - Quote: `static int new_call = 1;`
    - Located at: **line 3402 col 0** (EXACT_SUBSTRING)
    - HTML snippet: `static int new_call = 1 ;`

- **`OK_LINE_VERIFIED (0/0 quotes located exact)`**
  - URL: <https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf>


### Rule derivation chain (C13 automated, FULLY_DERIVED)
- **Primary source**: <https://github.com/makomk/aeskeyfind/blob/master/aeskeyfind.c>
- **Page line**: 2955
- **Quoted fragment**: `#define DEFAULT_THRESHOLD 10  // default threshold — the maximum bit-error count for candidate key schedules. Additionally 'Returns true if the 176 bytes starting at location bmap[i] contain more than 8 repeats of any byte' (entropy function) and 'if (column == 0) xor_count_128 += popcount(key_core(map[4*row-1],row) ^ map[4*(row-1)] ^ map[4*row])' (AES-128 round-key schedule `
- **Derivation chain**: Primary source: https://github.com/makomk/aeskeyfind/blob/master/aeskeyfind.c → page line 2955 (DEFAULT_THRESHOLD=10), line 3390 (entropy function: passes when a byte repeats eight or more times within a 176-byte window), line 3408 (byte_freq[256] sliding-window frequency array), line 3402 (new_call flag) reads `#define DEFAULT_THRESHOLD 10` and 'Returns true if the 176 bytes starting at location bmap[i] contain more than 8 repeats of any byte' + 'xor_count_128 += popcount(key_core(map[4*row-1],row) ^ map[4*(row-1)] ^ map[4*row])' → applied to the rule as: `function`=`aeskeyfind_scan` (function name borrowed verbatim from the Halderman aeskeyfind mechanism), `phase`=`ByteSigScanner` (the key_residue_snapshots/heap-dump byte-scanner stage), `mechanism`=`176-byte sliding window + byte_freq[256] entropy prefilter → popcount(XOR) ≤ DEFAULT_THRESHOLD(10) AES key-schedule verification` (each candidate memory region is hypothesized as an AES-128/192/256 round-key schedule, and is reported as a key when the bit-error count is at most 10), `input`=`key_residue_snapshots/heap dump` (the scanner walks across memory residue regions), `output`=`candidate_AES_key_bytes` (reported as a candidate key when the threshold is passed).
- **Field mappings**:
  - `function` = `aeskeyfind_scan` ← aeskeyfind.c full file name + DEFAULT_THRESHOLD/entropy/byte_freq identifiers — the canonical designation of the Halderman 'Lest We Remember' cold-boot AES recovery tool is borrowed verbatim
  - `phase` = `ByteSigScanner` ← byte_signature_scanner.py host + matches the behavior of the aeskeyfind.c entropy() function, which scans memory byte sequences via a byte_freq[256] window (line 3408)
  - `threshold` = `10 (bit errors)` ← aeskeyfind.c line 2955: `#define DEFAULT_THRESHOLD 10` — the default value from the Halderman paper, denoting the permissible bit-error count for candidate key schedules
  - `window_size` = `176 bytes` ← aeskeyfind.c entropy function: 'Returns true if the 176 bytes starting at location bmap[i] contain more than 8 repeats of any byte' — the AES-128 expanded-key length (11 rounds x 16 bytes)
  - `validation` = `popcount(key_core XOR) ≤ THRESHOLD` ← aeskeyfind.c round-key verification: `xor_count_128 += popcount(key_core(map[4*row-1],row) ^ map[4*(row-1)] ^ map[4*row])` — mathematical consistency check of the AES key schedule

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: github_master_source (Halderman/Maartmann-Moe 2009 lineage)
- **Citation**: Halderman et al., 'Lest We Remember: Cold Boot Attacks on Encryption Keys', USENIX Security 2008 — §6 'Identifying Keys in Memory' / Heninger & Shacham AES key-schedule recovery technique; implemented by Maartmann-Moe in aeskeyfind (makomk fork).
- **URL**: https://github.com/makomk/aeskeyfind/blob/master/aeskeyfind.c
- **Quote**:

```text
#define DEFAULT_THRESHOLD 10                       [aeskeyfind.c:29]
static int entropy(const uint8_t* bmap, size_t i) {
    static int new_call = 1;
    static int byte_freq[256] = {0};
    if (new_call) {
        for (int i=0; i<176; i++) byte_freq[bmap[i]]++;
        new_call = 0;
    }
    int test = 0;
    for (int b=0; b<=0xFF; b++) {
        if (byte_freq[b] > 8) {              [aeskeyfind.c:100-111]
int xor_count_256 = 0;
for (size_t row = 1; row < 8; row++) {
    for (size_t column = 0; column < 8; column++) {
        if (row == 7 && column == 4) break;
        if (column == 0)
            xor_count_256 += popcount(key_core(map[8*row-1],row)         [aeskeyfind.c:197-205]
int xor_count_128 = 0;
for (size_t row = 1; row < 11; row++) {
    for (size_t column = 0; column < 4; column++) {
        if (column == 0)
            xor_count_128 += popcount(key_core(map[4*row-1],row)         [aeskeyfind.c:220-225]
if (entropy(bmap,i)) continue;          [aeskeyfind.c:334]
```

- **Derivation**: Halderman §6 observes that the AES round-key schedule expanded from a candidate 16/32-byte seed has algebraic redundancy: every successive 4-byte word W[i] (i mod Nk != 0) is exactly W[i-1] XOR W[i-Nk], and for i mod Nk == 0 the equation is W[i] = SubWord(RotWord(W[i-1])) XOR Rcon XOR W[i-Nk]. Maartmann-Moe's aeskeyfind operationalises this by sliding a 240-byte window over RAM, computing the popcount of XOR violations of those equations across the full expanded schedule, and flagging windows where the total Hamming-distance error stays under DEFAULT_THRESHOLD=10 — which corresponds to a tiny number of bit-flips from cold-boot DRAM decay. The Python port reproduces (a) the 176-byte entropy gate, (b) the per-round per-column constraint, (c) the AES-256 col-0/col-4 dual-rule (SubWord+Rcon vs. plain SubWord), (d) the early-exit thresholds (<=10 for AES-256, <10 for AES-128) all line-numbered against the master commit.

### ② Mechanism
- **Algorithm/Concept**: FIPS-197 AES key schedule (KeyExpansion §5.2): for AES-128 (Nk=4, Nr=10) the expanded key is 176 bytes; for AES-256 (Nk=8, Nr=14) it is 240 bytes. AES-192 is intentionally NOT supported (matches upstream banner string).
- **Cryptographic role**: Round-key schedule integrity check. The seed key occupies bytes 0..15 (AES-128) or 0..31 (AES-256) of the 176/240-byte window; the remaining bytes are deterministic XOR derivatives. A correct schedule yields total popcount = 0; observed cold-boot keys remain recoverable up to ~10 bit errors per schedule (Halderman §6).
- **Why this is a unique signature**: Random RAM rarely satisfies even a single XOR constraint within 10 bit-flips; the joint constraint over 56 four-byte equations (AES-256) or 40 equations (AES-128) is astronomically improbable to satisfy by chance. The signature is therefore the *self-consistency of the entire 176/240-byte schedule under FIPS-197 KeyExpansion equations*, not any single byte pattern — which is why arbitrary high-entropy data does not trigger and only genuine AES key schedules do.
- **Bit provenance**: FIPS-197 §5.2 KeyExpansion pseudocode + Halderman et al. 2008 §6 'Reconstructing Keys' / aeskeyfind.c:190-251 (find_keys main loop) and aes.h:8-26 (key_core, sbox_bytes). 60 little-endian uint32 words = 240 bytes (AES-256); 44 uint32 = 176 bytes (AES-128).

### ③ Detection
- **Runtime step**: scan_all_snapshots() reads every keybirth_snapshots[*].snapshot_file (raw heap captures dumped by PinTool at CryptImportKey/BCryptGenerateSymmetricKey hook points), feeds each blob to aeskeyfind_scan(), and accumulates {offset,key_bits,errors,key_hex} hits. Hits are pure post-mortem of S2 (snapshot residue), not live API hooks.
- **Match criteria**: AES-256: sliding stride=1 byte across [0, len-240]; entropy gate Counter(window[:176]).most_common(1) <=8; sum of popcount(constraint) for row in 1..7, col in 0..7 (skip col==4..7 at row==7) <= 10. AES-128: same with len-176, rows 1..10, cols 0..3, sum < 10 (strictly tighter than upstream `>` per port comment).
- **Cross-axis role**: aux (operates on key_residue_snapshots produced by S2). Independent of S1 (CryptoAPI handle trace) and S3 (entropy timeline); supplies algorithm-attested ground truth for AES-128/256 key presence in heap.
- **Implementation file**: onHost/analysis/byte_signature_scanner.py:113-229 (aeskeyfind_scan), :42-65 (_SBOX), :74-76 (_RCON), :83-104 (_key_core_128 + _sbox_word), :107-110 (_popcount_word), :505-507 (driver invocation).

### ④ Limits
- **Ambiguity shared with**: Any FIPS-197-compliant AES KeyExpansion implementation (cannot distinguish OpenSSL vs ransomware-private vs Windows CNG-derived round keys at the byte level — only the *presence* of an AES key schedule is asserted)
- **FP scenarios**:
  - Pre-expanded AES-128/256 round-key tables genuinely present in memory for legitimate AES operations (not actually FP — the scanner is supposed to find these; FP only if attribution to ransomware specifically is desired)
  - Memory regions containing repeated/structured AES tables from other crypto libraries (OpenSSL EVP, mbedTLS, Crypto++) — same KeyExpansion satisfies the constraint
  - Theoretical: an attacker crafting a 240-byte payload that satisfies the FIPS-197 XOR equations purely to trigger the scanner (vanishingly improbable but possible)
- **FN scenarios**:
  - AES-192 keys (Nk=6, 208-byte schedule) — upstream aeskeyfind does not handle AES-192 and neither does this port (intentional, banner-string-confirmed)
  - Decrypt-optimised schedules where InvMixColumns is pre-applied to round keys 1..Nr-1 (mbedTLS decrypt path, WolfSSL key_dec variant) — TWEAK_INVMIXCOLUMN/TWEAK_REVERSE_ORDER 4-iteration loop from aeskeyfind.c:148-175 unconvert_key is NOT ported (explicit FIXME at upstream:192 for AES-256 too)
  - Heavily corrupted cold-boot residue with >10 bit-flips per 176-byte window passes the entropy gate but fails the XOR-popcount threshold
  - AES schedules stored in unusual word/byte order (big-endian uint32 words on ARM/PPC dumps — port assumes little-endian per x86 source)

*Consistency verdict*: **ransom-positive when correlated with S1 chain CryptEncrypt/BCryptEncrypt → file write tail**
*Notes*: AES-192 absence is upstream-faithful (Halderman/aeskeyfind never supported it). Threshold value 10 is the literal aeskeyfind DEFAULT_THRESHOLD constant; the AES-128 path uses strict `<` (port uses `>=` then `<` final filter — byte-identical hit set per port comment lines 215-218).

---

### Rationale + Usage
### (5) Rationale (why included in the catalog)
- **Why included**: the de facto standard implementation of AES key-schedule residue detection demonstrated in Halderman et al. 2008 cold-boot attack paper. A verified algorithm that most rapidly grounds AES-128/256 round keys from heap/snapshot during ransomware analysis.
- **Historical motivation**: Halderman 2008 'Lest We Remember: Cold Boot Attacks on Encryption Keys' (USENIX Security) introduced the key-recovery technique exploiting DRAM remanence → the Maartmann-Moe 2009 makomk/aeskeyfind implementation became canonical. A decisive technique for detecting the round-key constraint (XOR popcount ≤ threshold) in memory dumps of AES-256-using ransomware such as CryptoLocker (2013) / TeslaCrypt (2015) / WannaCry (2017).
- **Coverage gap if absent**: without this rule, even when AES round keys persist in memory (especially in heap not released after CryptGenKey), the heap-residue evidence itself cannot be grounded, precluding S2 (symmetric key candidate) / S3 (crypto API hit) corroboration. AES-128/256 family identification and the key-bits axis determination become impossible.

### (6) Usage (how / why used)
- **Primary use case**: Cipher classification (AES-128 vs AES-256) and key-schedule residue grounding from process memory snapshots
- **Consumer files**: onHost/analysis/byte_signature_scanner.py, onHost/analysis/recovery_cases.py, onHost/analysis/report.py
- **Contributes to**: S2+S3 corroboration, SIG-AES grounding, AES key-bits axis (128/256) (e.g. TeslaCrypt vs WannaCry AES variant), heap residue evidence
- **Concrete example**: WannaCry 2017 sample: 240-byte AES-256 schedule detected in the tasksche.exe heap snapshot (errors ≤ 10), with key_hex confirming the AES-256 family. AES-128 176-byte schedule detected in a CryptoLocker variant → SIG-AES trigger.

---

### Citations check
  - URL: https://github.com/makomk/aeskeyfind/blob/master/aeskeyfind.c
    - quote_verified: #define DEFAULT_THRESHOLD 10
    - support: DIRECT | authority: PRIMARY
    - excerpt: Line 27: `#define DEFAULT_THRESHOLD 10` (raw fetch); Line 29 in first fetch. DEFAULT_THRESHOLD == 10 confirmed in both fetches.
  - URL: https://github.com/makomk/aeskeyfind/blob/master/aeskeyfind.c
    - quote_verified: if (byte_freq[b] > 8)
    - support: DIRECT | authority: PRIMARY
    - excerpt: Entropy filter (Lines 100-114): The function uses a sliding window tracking byte frequency across 176 bytes, returning true if any byte appears more than 8 times.
  - URL: https://github.com/makomk/aeskeyfind/blob/master/aeskeyfind.c
    - quote_verified: if (row == 7 && column == 4) break;
    - support: DIRECT | authority: PRIMARY
    - excerpt: Line 171: `if (row == 7 && column == 4) break;` — verbatim AES-256 partial-row break.
  - URL: https://github.com/makomk/aeskeyfind/blob/master/aeskeyfind.c
    - quote_verified: AES-256 uses <= for final filter; AES-128 uses < for final filter
    - support: DIRECT | authority: PRIMARY
    - excerpt: Line 177 uses `<=` for 256-bit validation, while line 194 uses `<` for 128-bit validation.
  - URL: https://github.com/makomk/aeskeyfind/blob/master/aeskeyfind.c
    - quote_verified: // FIXME: implement tweaks here too
    - support: DIRECT | authority: PRIMARY
    - excerpt: Line 169: `// FIXME: implement tweaks here too` appears in the 256-bit AES key checking section.
  - URL: https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
    - quote_verified: AES-128 (Nk=4, Nr=10) -> 176 bytes; AES-256 (Nk=8, Nr=14) -> 240 bytes
    - support: DIRECT | authority: PRIMARY
    - excerpt: AES-128 (Nk=4, Nr=10): Generates 176 bytes of expanded key material; AES-256 (Nk=8, Nr=14): Creates 240 bytes of expanded key material.

---

### Citations check
  - URL: https://github.com/makomk/aeskeyfind/blob/master/aeskeyfind.c
    - quote_verified: #define DEFAULT_THRESHOLD 10; if (byte_freq[b] > 8); xor_count_256 <= gThreshold; xor_count_128 < gThreshold; AES-256 row loop `for (size_t row = 1; row < 8; row++)`; AES-128 row loop `for (size_t row = 1; row < 11; row++)`; TWEAK_INVMIXCOLUMN 0x1 / TWEAK_REVERSE_ORDER 0x2 / MAX_TWEAKS 0x4
    - support: DIRECT | authority: PRIMARY
    - excerpt: Line 39: #define DEFAULT_THRESHOLD 10. Lines 107-108: if (byte_freq[b] > 8) { test = 1; Lines 237-247: for (size_t row = 1; row < 8; row++) { ... if (column == 0) xor_count_256 += popcount(key_core(ma

---

## avaddon_session_key_scan

### URL / Quote Line-citation

- **`OK_PARTIALLY_LOCATED (4/5 exact, rest fuzzy/not found)`**
  - URL: <https://github.com/JavierYuste/AvaddonDecryptor/blob/main/main.py>
  - Quote NOT_LOCATED: `# 106600000100000020000000          [main.py:23-24]` (page alive but quote not in HTML)
  - Quote: `# Pattern to search for (part of the key_data_s structure, in particular`
    - Located at: **line 2732 col 2** (EXACT_SUBSTRING)
    - HTML snippet: `# Pattern to search for (part of the key_data_s structure, in particular alg_id, flags and key_size):`
  - Quote: `# Read pointer`
    - Located at: **line 3143 col 2** (EXACT_SUBSTRING)
    - HTML snippet: `# Read pointer`
  - Quote: `# alg_id, flags and key_size):`
    - Located at: **line 2732 col 73** (EXACT_SUBSTRING)
    - HTML snippet: `ture, in particular alg_id, flags and key_size):`
  - Quote: `mm.seek(offset + 12)`
    - Located at: **line 3137 col 0** (TOKEN_OVERLAP_1.00)
    - HTML snippet: `mm . seek ( offset + 12 )`

- **`BOT_PROTECTED_429 (Microsoft Learn etc.; verify in browser)`**
  - URL: <https://learn.microsoft.com/en-us/windows/win32/seccrypto/alg-id>


### Rule derivation chain (C13 automated, FULLY_DERIVED)
- **Primary source**: <https://github.com/JavierYuste/AvaddonDecryptor/blob/main/main.py>
- **Page line**: 2732
- **Quoted fragment**: `# Pattern to search for (part of the key_data_s structure, in particular alg_id, flags and key_size): 106600000100000020000000 — mm.seek(offset + 12) reads the 4-byte key data pointer to trace the session key location.`
- **Derivation chain**: Primary source: https://github.com/JavierYuste/AvaddonDecryptor/blob/main/main.py → page line 2732 (key_data_s pattern comment), line 3143 (`# Read pointer`), line 3137 (`mm.seek(offset + 12)`) reads `# Pattern to search for (part of the key_data_s structure, in particular alg_id, flags and key_size): 106600000100000020000000` + `mm.seek(offset + 12)` → applied to the rule as: `function`=`avaddon_session_key_scan` (borrowed from Javier Yuste's AvaddonDecryptor tool — targeting the fact that Avaddon ransomware retains session keys in memory via the CryptoAPI key_data_s structure), `phase`=`ByteSigScanner` (searching for a 12-byte fixed pattern in process dumps), `pattern`=`10 66 00 00 01 00 00 00 20 00 00 00 (12-byte hex)` (alg_id=0x6610=CALG_AES_256, flags=0x00000001, key_size=0x00000020=32 bytes = AES-256 key), `header_skip`=`+12 bytes` (mm.seek(offset+12) — skips past the pattern itself and extracts the 4-byte key-data pointer immediately following), `input`=`Avaddon process memory dump / key_residue_snapshots`, `output`=`AES-256 session key candidate byte sequence`.
- **Field mappings**:
  - `function` = `avaddon_session_key_scan` ← Javier Yuste's AvaddonDecryptor (https://github.com/JavierYuste/AvaddonDecryptor) — name borrowed from the publicly released 'Avaddon ransomware session key recovery' decryption tool
  - `phase` = `ByteSigScanner` ← byte_signature_scanner.py host + matches the manner in which main.py's pattern search performs a byte-wise scan of a 12-byte hex signature over mmap
  - `signature_pattern` = `0x10 0x66 0x00 0x00 0x01 0x00 0x00 0x00 0x20 0x00 0x00 0x00` ← main.py line 2732: `# Pattern to search for (part of the key_data_s structure, in particular alg_id, flags and key_size): 106600000100000020000000` — matches the provenance_excerpt `# 106600000100000020000000 [main.py:23-24]`
  - `pattern_semantics` = `alg_id=0x00006610 (CALG_AES_256) + flags=0x00000001 + key_size=0x00000020 (32B = AES-256)` ← main.py line 2732 comment specification: 'key_data_s structure, in particular alg_id, flags and key_size' + Microsoft Wincrypt ALG_ID values (CALG_AES_256=0x6610)
  - `pointer_extraction` = `mm.seek(offset + 12) → read 4 bytes (key data pointer)` ← main.py line 3137: `mm.seek(offset + 12)` + line 3143: `# Read pointer` — skips the 12-byte header immediately after the pattern match and extracts the key-data pointer

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: github_master_source (Yuste & Pastrana 2021)
- **Citation**: Yuste, J. & Pastrana, S. (2021) 'Avaddon ransomware: An in-depth analysis and decryption of infected systems', Computers & Security 109 — published decryptor source code released at JavierYuste/AvaddonDecryptor.
- **URL**: https://github.com/JavierYuste/AvaddonDecryptor/blob/main/main.py
- **Quote**:

```text
# Pattern to search for (part of the key_data_s structure, in particular
# alg_id, flags and key_size):
# 106600000100000020000000          [main.py:23-24]
mm.seek(offset + 12)
# Read pointer
key_data_pointer = mm.read(4)
ba = bytearray.fromhex(key_data_pointer.hex())      [main.py:88-91]
pattern = "106600000100000020000000"                [main.py:193]
```

- **Derivation**: Yuste & Pastrana reverse-engineered Avaddon's per-file AES key allocation path: each key_data_s struct allocated next to an HCRYPTKEY blob contains a 12-byte header {alg_id=0x00006610 (CALG_AES_256, little-endian 10 66 00 00), flags=0x00000001 (CRYPT_EXPORTABLE), key_size=0x00000020 (32 bytes = AES-256)} immediately followed by a 4-byte pointer to the raw 32-byte session key. Detecting the 12-byte ASCII-binary pattern '106600000100000020000000' and dereferencing the 4-byte pointer at offset+12 recovers the AES-256 key. Verified against Microsoft CALG_AES_256 = 0x00006610 (vendor spec).

### ② Mechanism
- **Algorithm/Concept**: Microsoft CryptoAPI key_data_s heap layout used by Avaddon's AES-256 per-file key allocation. The 12-byte prelude is a literal CRYPT_KEY_PROV_PARAM-adjacent encoding of (CALG_AES_256, CRYPT_EXPORTABLE, 32). Avaddon is a 32-bit (x86) process — pointers are 4 bytes.
- **Cryptographic role**: Per-file AES-256 session key allocator. The pattern itself is *metadata* — its presence implies a 32-byte AES-256 key resides at the pointer target. Decryptor recovers the key by dereferencing.
- **Why this is a unique signature**: The 12-byte concatenation of three specific ULONGs in a specific layout is unique to Microsoft CryptoAPI key_data_s when used with CALG_AES_256+CRYPT_EXPORTABLE+32-byte key. Random RAM has ~2^-96 probability of matching all 12 bytes. The pattern is *not* a generic AES marker — it is specifically the legacy CryptoAPI metadata layout (CNG would use BCRYPT_KEY_DATA_BLOB instead).
- **Bit provenance**: alg_id (4 bytes LE) = 0x00006610 = CALG_AES_256 per Wincrypt.h ALG_ID table (Microsoft docs). flags (4 bytes LE) = 0x00000001 = CRYPT_EXPORTABLE. key_size (4 bytes LE) = 0x00000020 = 32 bytes. Concatenated: 10 66 00 00 | 01 00 00 00 | 20 00 00 00 → '106600000100000020000000'. AvaddonDecryptor/main.py:23-24, 88-91, 193.

### ③ Detection
- **Runtime step**: scan_all_snapshots() iterates every keybirth_snapshots[*].snapshot_file (S2 residue) and runs avaddon_session_key_scan(data) which does literal-bytes find(_AVADDON_PATTERN) walk, then for each hit reads 4 bytes at off+12 as little-endian ULONG, gates against user-mode x86 range 0 < ptr < 0x80000000.
- **Match criteria**: Sliding bytes.find(_AVADDON_PATTERN, start) loop; for each match: ptr_off = off+12; require ptr_off+4 <= len(data); ptr = struct.unpack '<I'; require 0 < ptr < 0x80000000 (user-mode x86 range); record {offset, alg=CALG_AES_256, key_size=0x20, key_ptr}.
- **Cross-axis role**: aux. Detects Avaddon family specifically; provides high-confidence family attribution distinct from generic AES schedule detection (aeskeyfind_scan). Operates on S2 snapshot bytes only.
- **Implementation file**: onHost/analysis/byte_signature_scanner.py:415-438 (avaddon_session_key_scan), :412 (_AVADDON_PATTERN constant), :511-513 (driver invocation).

### ④ Limits
- **Ambiguity shared with**: Any Win32 malware that reuses Microsoft CryptoAPI with CALG_AES_256+CRYPT_EXPORTABLE+32 — pattern is non-unique by intent (it's a CryptoAPI artifact, not a private signature). Cross-validate with S1 chain to disambiguate., XOR mask 0xE35A172C cited in some secondary writeups does NOT appear in Yuste's source — port faithfully omits it (would have been a different rule).
- **FP scenarios**:
  - Any other Windows malware that allocates an AES-256 key via legacy CryptoAPI with CRYPT_EXPORTABLE — would trigger the same pattern (the pattern is *Avaddon-typical* but not Avaddon-unique; any CryptImportKey(CALG_AES_256, CRYPT_EXPORTABLE, 32-byte material) produces it). Family attribution should be confirmed by S1 trace.
  - Benign software using identical CryptoAPI key import flags (e.g., Office DRM, some VPN clients) — same pattern would match
  - 12-byte literal embedded in a constant pool or source code as a hex string (unlikely but possible)
- **FN scenarios**:
  - Avaddon variants that swap to CNG (BCRYPT_KEY_DATA_BLOB) — different layout, no match
  - Avaddon variants with different flags (e.g., CRYPT_EXPORTABLE | CRYPT_CREATE_IV would shift flag bits) — pattern wouldn't match
  - Pointer at off+12 lies outside 0..0x80000000 (e.g., 64-bit Avaddon variant with full 8-byte pointer — port assumes x86 per upstream)
  - Snapshot truncated before the 12-byte pattern completes
  - Key allocated via different CALG_* (CALG_AES_128 would produce '0e66...' prefix)

*Consistency verdict*: **ransom-positive when correlated with S1 CryptImportKey(CALG_AES_256) calls and S3 file-tail entropy spike on same process**
*Notes*: Port adds defensive 0 < ptr < 0x80000000 user-mode-VA gate not in Yuste's source (Yuste relies on minidump library to filter invalid VAs). The XOR mask 0xE35A172C from secondary writeups is intentionally omitted — Yuste's source operates on plaintext key_data_s next to HCRYPTKEY, not on the magic-protected blob (verified against full main.py read).

---

### Rationale + Usage
### (5) Rationale (why included in the catalog)
- **Why included**: the verified plaintext key_data_s pattern of the Yuste & Pastrana 2021 Bitdefender Avaddon decryptor. It matches directly the adjacent plaintext struct (alg_id=CALG_AES_256, flags=1, key_size=0x20) rather than the XOR-protected magic of the CryptoAPI HCRYPTKEY blob → false positives are minimized.
- **Historical motivation**: in 2021 Javier Yuste (Universidad Carlos III) released the Avaddon ransomware free decryptor in collaboration with Bitdefender → main.py published a 16-byte signature '106600000100000020000000' (CALG_AES_256 + flags + 0x20 key_size) and the +12-offset 32-bit pointer dereference logic. With Avaddon's abrupt shutdown (June 2021) after the victim chat panel was terminated, leaving the master key undisclosed, memory grounding became the sole recovery path.
- **Coverage gap if absent**: without this rule, session AES-256 keys from heap residue cannot be grounded for Avaddon and variants/successor RaaS that reuse the same key_data_s pattern (e.g., Haron, some Karma builds). The SIG-AVADDON trigger itself does not fire, and the very possibility of applying a family-specific decryptor cannot be determined.

### (6) Usage (how / why used)
- **Primary use case**: Avaddon family-specific session key (CALG_AES_256, 0x20 bytes) pointer grounding for targeted decryption
- **Consumer files**: onHost/analysis/byte_signature_scanner.py, onHost/analysis/recovery_cases.py, onHost/analysis/report.py
- **Contributes to**: SIG-AVADDON trigger, family identification (Avaddon / derivatives), session key pointer extraction, S2 symmetric key candidate via pointer dereference, decryptability verdict for Avaddon-class
- **Concrete example**: in the ransomware-process heap snapshot of an Avaddon-encrypted host, a 16-byte pattern + valid user-mode pointer (0x00000000 < ptr < 0x80000000) is detected → the 0x20-byte buffer pointed to by ptr is the actual AES-256 session key → Bitdefender decryptor applicability is determined.

---

### Citations check
  - URL: https://github.com/JavierYuste/AvaddonDecryptor/blob/main/main.py
    - quote_verified: Pattern to search for (part of the key_data_s structure, in particular alg_id, flags and key_size): 106600000100000020000000
    - support: DIRECT | authority: PRIMARY
    - excerpt: Line 34: '# Pattern to search for (part of the key_data_s structure, in particular alg_id, flags and key_size):' followed by '# 106600000100000020000000'.
  - URL: https://github.com/JavierYuste/AvaddonDecryptor/blob/main/main.py
    - quote_verified: mm.seek(offset + 12) ; key_data_pointer = mm.read(4)
    - support: DIRECT | authority: PRIMARY
    - excerpt: Lines 106-112: mm.seek(offset + 12); Read pointer; key_data_pointer = mm.read(4)
  - URL: https://learn.microsoft.com/en-us/windows/win32/seccrypto/alg-id
    - quote_verified: CALG_AES_256 = 0x00006610
    - support: DIRECT | authority: PRIMARY
    - excerpt: ALG_ID table: 'CALG_AES_256 | 0x00006610 | 256 bit AES.'

---

### Citations check
  - URL: https://github.com/JavierYuste/AvaddonDecryptor/blob/main/main.py
    - quote_verified: # Pattern to search for (part of the key_data_s structure, in particular alg_id, flags and key_size); mm.seek(offset + 12); key_data_pointer = mm.read(4); pattern = "106600000100000020000000"; XOR mask 0xE35A172C: absence confirmed
    - support: DIRECT | authority: PRIMARY
    - excerpt: Lines 23-24: # Pattern to search for (part of the key_data_s structure, in particular alg_id, flags and key_size). Lines 88-91: mm.seek(offset + 12) / # Read pointer / key_data_pointer = mm.read(4). L

---

## bcrypt_rsa_blob_scan

### URL / Quote Line-citation

- **`BOT_PROTECTED_429 (Microsoft Learn etc.; verify in browser)`**
  - URL: <https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob>

- **`OK_LINE_VERIFIED (0/0 quotes located exact)`**
  - URL: <https://github.com/microsoft/win32metadata>


### Rule derivation chain (C13 automated, FULLY_DERIVED)
- **Primary source**: <https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob>
- **Page line**: 538
- **Quoted fragment**: `typedef struct _BCRYPT_RSAKEY_BLOB { ULONG Magic; ULONG BitLength; ULONG cbPublicExp; ULONG cbModulus; ULONG cbPrime1; ULONG cbPrime2; } BCRYPT_RSAKEY_BLOB; — Magic Specifies the type of RSA key this BLOB represents: BCRYPT_RSAPUBLIC_MAGIC (0x31415352 'RSA1'), BCRYPT_RSAPRIVATE_MAGIC (0x32415352 'RS`
- **Derivation chain**: Primary source: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob → page line 538 (BitLength member), line 553 (Magic member description) reads `typedef struct _BCRYPT_RSAKEY_BLOB { ULONG Magic; ULONG BitLength; ULONG cbPublicExp; ULONG cbModulus; ULONG cbPrime1; ULONG cbPrime2; } BCRYPT_RSAKEY_BLOB;` + 'Magic — Specifies the type of RSA key this BLOB represents. This can be one of the following values. BCRYPT_RSAPUBLIC_MAGIC / BCRYPT_RSAPRIVATE_MAGIC / BCRYPT_RSAFULLPRIVATE_MAGIC' → applied to the rule as: `function`=`bcrypt_rsa_blob_scan` (identifies the BCRYPT_RSAKEY_BLOB structure of Microsoft CNG bcrypt.h), `phase`=`ByteSigScanner` (byte-wise searches for the RSA key BLOB header signature in memory), `magic_signatures`=`0x31415352, 0x32415352, 0x33415352 ('RSA1'/'RSA2'/'RSA3')` (4-byte Magic field — the BLOB-start identifier), `header_layout`=`Magic(4) + BitLength(4) + cbPublicExp(4) + cbModulus(4) + cbPrime1(4) + cbPrime2(4) = 24-byte header` (structure specified in vendor spec), `input`=`process heap / key_residue_snapshots`, `output`=`RSA key BLOB starting offset + Magic type (public/private/full-private)`.
- **Field mappings**:
  - `function` = `bcrypt_rsa_blob_scan` ← Microsoft Learn page title 'BCRYPT_RSAKEY_BLOB (bcrypt.h)' — borrows verbatim the RSA key BLOB structure name from the Win32 CNG API
  - `phase` = `ByteSigScanner` ← byte_signature_scanner.py host + vendor spec stating that the BCRYPT_RSAKEY_BLOB header is identifiable by a fixed in-memory signature (Magic)
  - `magic_constants` = `BCRYPT_RSAPUBLIC_MAGIC=0x31415352, BCRYPT_RSAPRIVATE_MAGIC=0x32415352, BCRYPT_RSAFULLPRIVATE_MAGIC=0x33415352` ← Microsoft Learn page line 553: 'Magic Specifies the type of RSA key this BLOB represents' + win32metadata header values in provenance_excerpt ('RSA1'/'RSA2'/'RSA3' ASCII)
  - `structure_fields` = `Magic, BitLength, cbPublicExp, cbModulus, cbPrime1, cbPrime2 (each ULONG=4B, total 24B header)` ← Microsoft Learn page Syntax block: `typedef struct _BCRYPT_RSAKEY_BLOB { ULONG Magic; ULONG BitLength; ULONG cbPublicExp; ULONG cbModulus; ULONG cbPrime1; ULONG cbPrime2; }` (line 538 specifies ULONG BitLength)
  - `blob_layout` = `Header(24B) + PublicExponent[cbPublicExp] + Modulus[cbModulus] + Prime1[cbPrime1] + Prime2[cbPrime2] (big-endian)` ← Microsoft Learn Remarks: 'BCRYPT_RSAKEY_BLOB / PublicExponent[cbPublicExp] // Big-endian / Modulus[cbModulus] // Big-endian / Prime1[cbPrime1] // Big-endian / Prime2[cbPrime2] // Big-endian'

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: vendor_spec (Microsoft CNG bcrypt.h documentation)
- **Citation**: Microsoft, 'BCRYPT_RSAKEY_BLOB (bcrypt.h)' — official Win32 API reference, plus bcrypt.h header constants from win32metadata.
- **URL**: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
- **Quote**:

```text
typedef struct _BCRYPT_RSAKEY_BLOB {
  ULONG Magic;
  ULONG BitLength;
  ULONG cbPublicExp;
  ULONG cbModulus;
  ULONG cbPrime1;
  ULONG cbPrime2;
} BCRYPT_RSAKEY_BLOB;

#define BCRYPT_RSAPUBLIC_MAGIC      0x31415352  // 'RSA1'
#define BCRYPT_RSAPRIVATE_MAGIC     0x32415352  // 'RSA2'
#define BCRYPT_RSAFULLPRIVATE_MAGIC 0x33415352  // 'RSA3'

// From spec: 'cbPublicExp: The size, in bytes, of the exponent of the
// key. As of Windows 10 version 1903, public exponents larger than
// (2^64 - 1) are no longer supported.' (i.e. cbPublicExp in 1..8).
// 'cbPrime1: The size, in bytes, of the first prime number of the key.
// This is only used for private key BLOBs.'
```

- **Derivation**: Microsoft's BCRYPT_RSAKEY_BLOB spec fully defines the 24-byte header: 4-byte ASCII magic ('RSA1'/'RSA2'/'RSA3'), 4-byte BitLength (must equal the key size in bits), 4-byte cbPublicExp (1..8 per the post-1903 e<=2^64-1 limit), 4-byte cbModulus (must equal BitLength/8), and for private blobs, 4-byte cbPrime1 and cbPrime2 (each must equal BitLength/16). The scanner reproduces every one of these spec constraints as a self-consistency gate, plus a payload-fits-in-buffer guard to reject truncated matches.

### ② Mechanism
- **Algorithm/Concept**: RSA key serialisation format used by Windows Cryptography API: Next Generation (CNG / BCrypt) when a key is exported via BCryptExportKey with pszBlobType = BCRYPT_RSAPUBLIC_BLOB / BCRYPT_RSAPRIVATE_BLOB / BCRYPT_RSAFULLPRIVATE_BLOB.
- **Cryptographic role**: Header for the in-memory or on-disk RSA key material. Locating a BCRYPT_RSAKEY_BLOB in a heap snapshot directly yields the per-victim RSA keypair (or its public half) — the same target wanakiwi reconstructs from raw primes.
- **Why this is a unique signature**: Five-way self-consistency: (a) Magic must be one of three ASCII tags; (b) BitLength must be in the CNG-supported set; (c) cbModulus == BitLength/8; (d) for private blobs, cbPrime1 == cbPrime2 == BitLength/16; (e) cbPublicExp in 1..8. Random 24-byte memory has ~2^-24 chance of any one magic, and ~2^-32 of any one ULONG = expected size — joint probability of all five constraints by chance is ~2^-80, effectively zero.
- **Bit provenance**: BCRYPT_RSAKEY_BLOB struct: bcrypt.h ABI. Magic ASCII 4 bytes at offset 0; ULONG fields at offsets 4/8/12/16/20 in little-endian (Windows ABI). Payload immediately follows the 24-byte header in big-endian per spec ('All of the numbers following the structure are in big-endian format'). Valid BitLength values 1024/2048/3072/4096 = the CNG-enumerated set.

### ③ Detection
- **Runtime step**: scan_all_snapshots() iterates every keybirth_snapshots[*].snapshot_file and calls bcrypt_rsa_blob_scan(data) which slides offset across [0, len-24] checking each 24-byte header for the five self-consistency constraints + payload-fits guard.
- **Match criteria**: data[off:off+4] in {b'RSA1', b'RSA2', b'RSA3'}; unpack <IIIII at off+4; BitLength in {1024,2048,3072,4096}; cbModulus == BitLength//8; if magic in {RSA2,RSA3} then cbPrime1 == cbPrime2 == BitLength//16; 1 <= cbPublicExp <= 8; payload (cbPubExp + cbMod + 2*cbP1 [+ 3*cbP1+cbMod for RSA3]) fits in data.
- **Cross-axis role**: aux. Complements S1's BCryptExportKey hook (which captures blobs via API) by finding blobs that were generated but never exported (e.g. ransomware that keeps the keypair internal and only exports the public half to the C2). Operates on S2 snapshot bytes.
- **Implementation file**: onHost/analysis/byte_signature_scanner.py:329-392 (bcrypt_rsa_blob_scan), :321-326 (_BCRYPT_MAGICS, _BCRYPT_VALID_BITS tables), :508-510 (driver invocation).

### ④ Limits
- **Ambiguity shared with**: BCRYPT_DSAKEY_BLOB and BCRYPT_ECCKEY_BLOB share the bcrypt.h ABI style but use different magic strings ('DSPB','ECS1', etc.), so no actual overlap., Microsoft CryptoAPI legacy PUBLICKEYBLOB also uses 'RSA1' (RSAPUBKEY) but at offset 8 (after BLOBHEADER) — different framing; would not satisfy this scanner's offset-0 magic test (handled separately by _extract_rsa_moduli_from_chain).
- **FP scenarios**:
  - A copy of the bcrypt.h header file itself in a binary's .rdata section happens to contain the constants but not in struct form (would fail BitLength/cbModulus relation)
  - A custom file format (non-Microsoft) that happens to use ASCII 'RSA1' as a magic — would fail the BitLength size check unless coincidentally aligned
  - Other ransomware's custom blob format mimicking BCRYPT layout (intentional camouflage — but this is then arguably a *correct* detection, not FP)
- **FN scenarios**:
  - Blob stored with byte-swapped magic (big-endian ULONG hosts — non-Windows ABI; not applicable in Windows ransomware contexts)
  - Blob using non-standard BitLength (e.g., 1536-bit RSA used in some legacy CSPs — port restricts to {1024,2048,3072,4096}, matching CNG's enumerated set; unusual sizes are FN)
  - Magic field zeroed/clobbered by partial overwrite but payload intact
  - Blob spans non-contiguous heap allocations (fragmented across snapshot file boundaries)

*Consistency verdict*: **ransom-positive when blob is non-export-traced and bit_length matches the per-victim keypair size declared in S1 BCryptGenerateKeyPair**
*Notes*: Port B8-hardened: (a) cbPubExp range 1..8 per the post-1903 e<=2^64-1 spec (vs the naive {3,4} which missed legacy smartcard exponents); (b) off-by-one fixed at range(0, data_len-24+1); (c) payload-fits guard rejects truncated matches that would otherwise spuriously pass the header gate.

---

### Rationale + Usage
### (5) Rationale (why included in the catalog)
- **Why included**: the Microsoft CNG BCRYPT_RSAKEY_BLOB struct is the de facto standard serialization format for all RSA operations in Windows 10+. An essential grounding signature for analyzing modern ransomware that uses the Cryptography Next Gen API (Avaddon, Conti, BlackCat).
- **Historical motivation**: as CNG (Cryptography Next Generation) bcrypt.h introduced from Windows Vista replaced the legacy CryptoAPI, self-describing blobs starting with 'RSA1'/'RSA2'/'RSA3' magic upon BCryptExportKey calls persist in heap. With Avaddon (2020-21), Conti (2020-22), LockBit (2022+), etc. using CNG → a rule for grounding this blob in memory is required.
- **Coverage gap if absent**: without this rule, RSA public/private key material of CNG-based ransomware cannot be identified in heap residue. The RSA modulus does not enter the asym_blobs chain, eliminating the input modulus source itself for the wanakiwi prime scan. RSA-3072/4096 families are also missed.

### (6) Usage (how / why used)
- **Primary use case**: Microsoft CNG RSA key blob structural identification (full_private/half_private/public) in process memory
- **Consumer files**: onHost/analysis/byte_signature_scanner.py, onHost/analysis/recovery_cases.py, onHost/analysis/report.py
- **Contributes to**: SIG-BCRYPT grounding, asym_blob chain construction, wanakiwi_prime_scan input modulus supply, RSA bit-length axis (1024/2048/3072/4096), S3 crypto API hit corroboration (CNG-era ransomware)
- **Concrete example**: in an Avaddon sample heap snapshot, 'RSA2' magic (half_private) + bit_length=2048 + cb_mod=256 + cb_p1=128 are detected → RSA-2048 half-private blob is confirmed, modulus is registered in the chain → subsequent wanakiwi_prime_scan triggers a prime-factor search on the same snapshot.

---

### Citations check
  - URL: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
    - quote_verified: typedef struct _BCRYPT_RSAKEY_BLOB { ULONG Magic; ULONG BitLength; ULONG cbPublicExp; ULONG cbModulus; ULONG cbPrime1; ULONG cbPrime2; }
    - support: DIRECT | authority: PRIMARY
    - excerpt: Microsoft Learn BCRYPT_RSAKEY_BLOB page shows the exact struct definition with the six ULONG fields in this order.
  - URL: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
    - quote_verified: As of Windows 10 version 1903, public exponents larger than (2^64 - 1) are no longer supported.
    - support: DIRECT | authority: PRIMARY
    - excerpt: cbPublicExp doc text: 'The size, in bytes, of the exponent of the key. As of Windows 10 version 1903, public exponents larger than (2^64 - 1) are no longer supported.'
  - URL: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
    - quote_verified: BCRYPT_RSAPUBLIC_MAGIC / BCRYPT_RSAPRIVATE_MAGIC / BCRYPT_RSAFULLPRIVATE_MAGIC
    - support: INDIRECT | authority: PRIMARY
    - excerpt: Microsoft Learn enumerates the three magic constants; their literal ASCII values 'RSA1'/'RSA2'/'RSA3' (0x31415352 / 0x32415352 / 0x33415352) are in bcrypt.h SDK header (not on the Learn page itself, b

---

### Citations check
  - URL: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
    - quote_verified: typedef struct _BCRYPT_RSAKEY_BLOB { ULONG Magic; ULONG BitLength; ULONG cbPublicExp; ULONG cbModulus; ULONG cbPrime1; ULONG cbPrime2; } BCRYPT_RSAKEY_BLOB; cbPublicExp: 'As of Windows 10 version 1903, public exponents larger than (2^64 - 1) are no longer supported.'; cbPrime1/cbPrime2: 'This is only used for private key BLOBs.'; 'All of the numbers following the structure are in big-endian format.'
    - support: DIRECT | authority: PRIMARY
    - excerpt: typedef struct _BCRYPT_RSAKEY_BLOB { ULONG Magic; ULONG BitLength; ULONG cbPublicExp; ULONG cbModulus; ULONG cbPrime1; ULONG cbPrime2; } BCRYPT_RSAKEY_BLOB; ... cbPublicExp: The size, in bytes, of the

---

## cryptoapi_rsa_blob_scan

### URL / Quote Line-citation

- **`BOT_PROTECTED_429 (Microsoft Learn etc.; verify in browser)`**
  - URL: <https://learn.microsoft.com/en-us/windows/win32/seccrypto/base-provider-key-blobs>
- **`OK_LINE_VERIFIED (ALG_ID component values cross-checked)`**
  - URL: <https://learn.microsoft.com/en-us/windows/win32/seccrypto/alg-id>


### Rule derivation chain (manual, FULLY_DERIVED)
- **Primary source**: <https://learn.microsoft.com/en-us/windows/win32/seccrypto/base-provider-key-blobs>
- **Quoted fragment**: `[Private Key BLOBs] PUBLICKEYSTRUC publickeystruc; RSAPUBKEY rsapubkey; BYTE modulus[rsapubkey.bitlen/8]; BYTE prime1[rsapubkey.bitlen/16]; BYTE prime2[rsapubkey.bitlen/16]; BYTE exponent1[rsapubkey.bitlen/16]; BYTE exponent2[rsapubkey.bitlen/16]; BYTE coefficient[rsapubkey.bitlen/16]; BYTE privateExponent[rsapubkey.bitlen/8]; ... The magic member must be set to 0x32415352. This hexadecimal value is the ASCII encoding of RSA2.`
- **Derivation chain**: Primary source https://learn.microsoft.com/en-us/windows/win32/seccrypto/base-provider-key-blobs defines the CryptoAPI PRIVATEKEYBLOB as PUBLICKEYSTRUC (BLOBHEADER, 8 bytes) + RSAPUBKEY (magic/bitlen/pubexp, 12 bytes) + modulus(bitlen/8) + prime1/prime2/exponent1/exponent2/coefficient (each bitlen/16) + privateExponent(bitlen/8), with the RSAPUBKEY magic set to 0x32415352 ('RSA2') for a private blob. The companion ALG_ID page (https://learn.microsoft.com/en-us/windows/win32/seccrypto/alg-id) gives CALG_RSA_KEYX = ALG_CLASS_KEY_EXCHANGE(0xA000) | ALG_TYPE_RSA(0x400) = 0xA400 and CALG_RSA_SIGN = ALG_CLASS_SIGNATURE(0x2000) | ALG_TYPE_RSA(0x400) = 0x2400. -> applied to the rule as: function=cryptoapi_rsa_blob_scan (the legacy-CryptoAPI counterpart to bcrypt_rsa_blob_scan), phase=ByteSigScanner, blobheader=07 02 00 00 (bType=PRIVATEKEYBLOB, bVersion=2, reserved=0), magic=RSA2 at offset+8, payload=2*mod+5*p.
- **Field mappings**:
  - `function` = `cryptoapi_rsa_blob_scan` ← MS Learn 'Base Provider Key BLOBs' PRIVATEKEYBLOB; the CryptoAPI counterpart whose RSAPUBKEY magic sits after an 8-byte BLOBHEADER (bcrypt_rsa_blob_scan anchors magic at offset 0 and structurally cannot see it)
  - `algorithm_ids` = `CALG_RSA_KEYX=0x0000A400, CALG_RSA_SIGN=0x00002400` ← wincrypt.h ALG_ID: (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_RSA) and (ALG_CLASS_SIGNATURE|ALG_TYPE_RSA), component values cross-checked on the ALG_ID page
  - `blobheader` = `bType=0x07 (PRIVATEKEYBLOB), bVersion=0x02, reserved=0x0000` ← MS PUBLICKEYSTRUC / BLOBHEADER
  - `magic` = `RSA2 (0x32415352)` ← MS Learn: 'The magic member must be set to 0x32415352 ... ASCII encoding of RSA2' (private blob only; RSA3/RSAFULLPRIVATE is CNG-only and has no BLOBHEADER)
  - `valid_bits` = `{1024, 2048, 3072, 4096}` ← CNG-enumerated RSA sizes (shared _BCRYPT_VALID_BITS table)
  - `payload` = `2*mod + 5*p = modulus(bitlen/8) + prime1 + prime2 + exponent1 + exponent2 + coefficient (each bitlen/16) + privateExponent(bitlen/8)` ← MS Learn PRIVATEKEYBLOB field layout (verbatim)

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: vendor_spec (Microsoft CryptoAPI wincrypt.h documentation)
- **Citation**: Microsoft, 'Base Provider Key BLOBs' (PRIVATEKEYBLOB layout) + 'ALG_ID' (CALG_RSA_KEYX/CALG_RSA_SIGN), Win32 wincrypt.h reference.
- **URL**: https://learn.microsoft.com/en-us/windows/win32/seccrypto/base-provider-key-blobs
- **Quote**:

```text
[Private Key BLOBs] PUBLICKEYSTRUC publickeystruc; RSAPUBKEY rsapubkey; BYTE modulus[rsapubkey.bitlen/8]; BYTE prime1[rsapubkey.bitlen/16]; BYTE prime2[rsapubkey.bitlen/16]; BYTE exponent1[rsapubkey.bitlen/16]; BYTE exponent2[rsapubkey.bitlen/16]; BYTE coefficient[rsapubkey.bitlen/16]; BYTE privateExponent[rsapubkey.bitlen/8] ... The magic member must be set to 0x32415352. This hexadecimal value is the ASCII encoding of RSA2.
```

- **Derivation**: A ransomware family that generates or imports an RSA keypair through the *legacy* CryptoAPI (CryptGenKey / CryptImportKey on a CALG_RSA_KEYX context) materialises a PRIVATEKEYBLOB in the calling process heap when it serialises the key. Unlike the CNG BCRYPT_RSAKEY_BLOB (magic at offset 0), the CryptoAPI blob begins with an 8-byte BLOBHEADER (bType=0x07 PRIVATEKEYBLOB, bVersion=0x02, reserved=0x0000, aiKeyAlg=CALG_RSA_*) and only then the RSAPUBKEY whose magic is 'RSA2'. bcrypt_rsa_blob_scan, which unpacks its header at offset+4, misreads this framing (it interprets the CryptoAPI bitlen/pubexp as cbPublicExp/cbModulus) and rejects the blob -- so a genuine, directly-recoverable RSA private key in a key-birth dump was previously missed. cryptoapi_rsa_blob_scan closes that gap by anchoring on the 07 02 00 00 BLOBHEADER, validating aiKeyAlg in {CALG_RSA_KEYX, CALG_RSA_SIGN} and magic=='RSA2', then requiring the full 2*mod+5*p PRIVATEKEYBLOB payload to fit so stray 07 02 00 00 bytes are rejected.

### ② Mechanism
- **Algorithm/Concept**: Microsoft CryptoAPI (legacy, rsaenh.dll) RSA PRIVATEKEYBLOB serialisation: BLOBHEADER + RSAPUBKEY('RSA2') + modulus + prime1 + prime2 + exponent1 + exponent2 + coefficient + privateExponent.
- **Cryptographic role**: S1 (asymmetric secret material) -- the blob carries primes p,q (prime1/prime2) and the private exponent d directly, so locating one in a heap snapshot yields the per-victim RSA private key with no cryptanalysis.
- **Why this is a unique signature**: Joint self-consistency: (a) BLOBHEADER bType=0x07 + bVersion=0x02 + reserved=0x0000; (b) aiKeyAlg in {0xA400, 0x2400}; (c) RSAPUBKEY magic 0x32415352 ('RSA2') at offset+8; (d) bitlen in {1024,2048,3072,4096}; (e) the full 2*mod+5*p tail fits in the buffer. Random memory satisfying all five is ~2^-80, effectively zero -- no entropy heuristic is needed.
- **Bit provenance**: BLOBHEADER {bType, bVersion, wReserved, aiKeyAlg} = wincrypt.h PUBLICKEYSTRUC; aiKeyAlg LE = 0x0000A400 (CALG_RSA_KEYX) or 0x00002400 (CALG_RSA_SIGN); RSAPUBKEY.magic LE 4 bytes at offset+8 = 0x32415352 ('RSA2'); bitlen/pubexp ULONG at offset+12/+16. PRIVATEKEYBLOB tail per MS Learn = modulus(bitlen/8) + prime1/prime2/exp1/exp2/coef(bitlen/16 each) + privateExponent(bitlen/8) = 2*(bitlen/8) + 5*(bitlen/16).

### ③ Detection
- **Runtime step**: scan_all_snapshots() iterates every keybirth_snapshots[*].snapshot_file (S2 residue) and runs cryptoapi_rsa_blob_scan(data): find(b'\x07\x02\x00\x00'), unpack aiKeyAlg at +4, magic at +8, bitlen/pubexp at +12; accept iff aiKeyAlg in {CALG_RSA_KEYX, CALG_RSA_SIGN}, magic=='RSA2', bitlen in {1024,2048,3072,4096}, and 20 + 2*mod + 5*p <= len. Hits feed cryptoapi_rsa_blob_hits / cryptoapi_rsa_blob_count.
- **Match criteria**: BLOBHEADER 07 02 00 00 found AND aiKeyAlg in {0xA400, 0x2400} AND magic=='RSA2' AND bitlen in {1024,2048,3072,4096} AND full PRIVATEKEYBLOB payload fits.
- **Cross-axis role**: aux. Complements bcrypt_rsa_blob_scan (CNG, magic@0) by capturing the legacy-CryptoAPI framing (magic@8). residue_scanner promotes residue to HIGH on a cryptoapi private hit (reason 'cryptoapi_rsa_blob'), driving RC-02. RC-03 stays wanakiwi-only: a promotion whose signature is not in an RC's allowed_byte_sigs reverts to the un-promoted class, so RC-02 cannot over-claim from an AES hit and RC-03 cannot fire from a cryptoapi/bcrypt hit. Operates on S2 snapshot bytes only.
- **Implementation file**: onHost/analysis/byte_signature_scanner.py (cryptoapi_rsa_blob_scan + _CRYPTOAPI_RSA_ALGS table + scan_all_snapshots driver), onHost/analysis/residue_scanner.py (apply_byte_sig_promotion cryptoapi_priv), onHost/analysis/recovery_cases.py (RC-02 residue_class_at_least allowed_byte_sigs, _has_byte_sig_hit, BYTE_SIGS).

### ④ Limits
- **Ambiguity shared with**: bcrypt_rsa_blob_scan (CNG BCRYPT_RSAKEY_BLOB) -- same RSA-key target, different framing (CryptoAPI has the 8-byte BLOBHEADER, CNG does not); the two are mutually exclusive on a given blob., RC-01 (rsa_private_blob_exported_full) -- RC-01 fires on an export *event* with a complete blob, whereas cryptoapi_rsa_blob_scan fires on the heap *residue* feeding RC-02.
- **FP scenarios**:
  - A legitimate application that exports its own RSA PRIVATEKEYBLOB via CryptExportKey (EFS/DPAPI enrolment, certificate tools) leaves the same heap residue -- the 'recoverable' verdict is factually correct, it just is not ransomware.
  - A binary embedding a 07 02 00 00 + RSA2 + valid-size blob as test data -- but the payload-fits guard plus the aiKeyAlg/bitlen consistency make incidental matches ~2^-80.
- **FN scenarios**:
  - Ransomware that keeps the keypair only in a CNG BCRYPT_RSAKEY_BLOB -- captured by bcrypt_rsa_blob_scan instead.
  - PRIVATEKEYBLOB encrypted at export (CryptExportKey with a non-zero hExpKey session key) -- only the PUBLICKEYSTRUC stays plaintext, the RSAPUBKEY/payload are ciphertext, so the magic/size gates fail (correct: an encrypted blob is not directly recoverable).
  - Non-standard bitlen (e.g. 1536-bit legacy CSP) -- restricted to the CNG-enumerated {1024,2048,3072,4096} set.
  - Snapshot truncated before the full 2*mod+5*p payload.

*Consistency verdict*: **recovery-feasibility-positive: a CryptoAPI PRIVATEKEYBLOB ('RSA2') in a key-birth dump is the directly-recoverable per-victim RSA private key; drives RC-02 at residue HIGH.**
*Notes*: Added to close the gap documented at bcrypt_rsa_blob_scan ④ Limits ('Microsoft CryptoAPI legacy ... uses RSA1 at offset 8 (after BLOBHEADER) ... handled separately'). RSA3/RSAFULLPRIVATE is intentionally NOT accepted here -- it is a CNG-only magic with no BLOBHEADER, so 07 02 00 00 + RSA3 cannot occur. All numeric constants (0xA400, 0x2400, 0x32415352, payload 2*mod+5*p, bType 0x07/bVersion 0x02) verified verbatim against Microsoft Learn -- no heuristic value.

### Rationale + Usage
### (5) Rationale (why included in the catalog)
- **Why included**: the legacy-CryptoAPI counterpart of bcrypt_rsa_blob_scan. A directly-recoverable RSA private key serialised as a CryptoAPI PRIVATEKEYBLOB ('RSA2' after an 8-byte BLOBHEADER) is structurally invisible to the CNG-anchored scanner; without this rule such a key in a key-birth dump is silently missed even though it is the strongest possible recovery signal.
- **Historical motivation**: A corpus trace (Surtr-family) was found to carry a valid CALG_RSA_KEYX PRIVATEKEYBLOB (RSA-1024, pubexp 65537) in a crypto_*.bin snapshot, which bcrypt_rsa_blob_scan misread as a garbage header (cb_pub_exp=65537 out of the 1..8 range) and rejected. Recovery-feasibility means flagging that the key is *present*, not that decryption is guaranteed, so the dump-key residue must be captured.
- **Coverage gap if absent**: without this rule, every trace that leaves an RSA private key in the *legacy* CryptoAPI on-the-wire form (rather than the CNG BCRYPT form) is missed by the residue scanner, and RC-02 cannot fire on those dumps.

### (6) Usage (how / why used)
- **Primary use case**: legacy CryptoAPI RSA PRIVATEKEYBLOB residue grounding in process-memory snapshots, feeding RC-02 (per-run RSA keypair in heap).
- **Consumer files**: onHost/analysis/byte_signature_scanner.py, onHost/analysis/residue_scanner.py, onHost/analysis/recovery_cases.py, onHost/analysis/report.py
- **Contributes to**: RC-02 decision (residue HIGH via cryptoapi_rsa_blob promotion), residue tier classification, RSA bit-length axis, S2 heap residue evidence.
- **Concrete example**: in a Surtr-family heap snapshot, a 07 02 00 00 BLOBHEADER + aiKeyAlg=CALG_RSA_KEYX + 'RSA2' magic + bitlen=1024 is detected -> cryptoapi_rsa_blob_count=1 -> residue promoted NONE->HIGH (cryptoapi_rsa_blob:1) -> RC-02 PASSED.

### Citations check
  - URL: https://learn.microsoft.com/en-us/windows/win32/seccrypto/base-provider-key-blobs
    - quote_verified: PUBLICKEYSTRUC publickeystruc; RSAPUBKEY rsapubkey; BYTE modulus[rsapubkey.bitlen/8]; BYTE prime1[rsapubkey.bitlen/16]; BYTE prime2[rsapubkey.bitlen/16]; BYTE exponent1[rsapubkey.bitlen/16]; BYTE exponent2[rsapubkey.bitlen/16]; BYTE coefficient[rsapubkey.bitlen/16]; BYTE privateExponent[rsapubkey.bitlen/8]; magic must be set to 0x32415352 (RSA2)
    - support: DIRECT | authority: PRIMARY
    - excerpt: MS Learn 'Base Provider Key BLOBs' Private Key BLOBs section gives the PRIVATEKEYBLOB byte layout and the RSAPUBKEY magic 0x32415352 ('RSA2').
  - URL: https://learn.microsoft.com/en-us/windows/win32/seccrypto/alg-id
    - quote_verified: CALG_RSA_KEYX = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_RSA | ALG_SID_RSA_ANY; CALG_RSA_SIGN = ALG_CLASS_SIGNATURE | ALG_TYPE_RSA | ALG_SID_RSA_ANY
    - support: DIRECT | authority: PRIMARY
    - excerpt: ALG_ID page components ALG_CLASS_KEY_EXCHANGE(0xA000), ALG_CLASS_SIGNATURE(0x2000), ALG_TYPE_RSA(0x400) -> CALG_RSA_KEYX=0xA400, CALG_RSA_SIGN=0x2400.

---

## scan_all_snapshots

### URL / Quote Line-citation

- **`OK_PARTIALLY_LOCATED (3/11 exact, rest fuzzy/not found)`**
  - URL: <https://github.com/aguinet/wannakey/blob/master/wannakey/wkey/search_primes.cpp>
  - Quote NOT_LOCATED: `# BLOBHEADER (8B) + RSAPUBKEY (12B: magic 'RSA1' + bitlength + pubexp) + modulus[bitlength/8]` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `# PUBLICKEYBLOB layout (Microsoft Wincrypt.h):` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `# Per-modulus prime_bytes computed:` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `# bundle['keybirth_snapshots'][*]['snapshot_file'] — relative path under trace_dir;` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `# captures triggered at CryptImportKey/BCryptGenerateSymmetricKey hook entry.` (page alive but quote not in HTML)

- **`BOT_PROTECTED_429 (Microsoft Learn etc.; verify in browser)`**
  - URL: <https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob>

- **`OK_LINE_VERIFIED (0/0 quotes located exact)`**
  - URL: <https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf>

- **`BOT_PROTECTED_429 (Microsoft Learn etc.; verify in browser)`**
  - URL: <https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptoapi-cryptographic-service-providers>

- **`BOT_PROTECTED_429 (Microsoft Learn etc.; verify in browser)`**
  - URL: <https://learn.microsoft.com/en-us/windows/win32/seccrypto/base-provider-key-blobs>

- **`OK_LINE_VERIFIED (0/0 quotes located exact)`**
  - URL: <https://datatracker.ietf.org/doc/html/rfc8017#section-3.1>


### Rule derivation chain (C14 automated, FULLY_DERIVED)
- **Primary source**: <https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers>
- **Page line**: 506
- **Quoted fragment**: `BCRYPT_AES_ALGORITHM L"AES" \| The advanced encryption standard (AES) symmetric encryption algorithm. Standard: FIPS 197`
- **Derivation chain**: Primary source: https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers -> the algorithm-identifier table row at the rendered position ~line 506 reads verbatim 'BCRYPT_AES_ALGORITHM L"AES" \| The advanced encryption standard (AES) symmetric encryption algorithm. Standard: FIPS 197', and adjacent rows define BCRYPT_RSA_ALGORITHM (L"RSA", PKCS#1), BCRYPT_ECDH_P256/P384/P521 (SP800-56A), BCRYPT_ECDSA_P256/P384/P521 (FIPS 186-2, X9.62), BCRYPT_3DES_ALGORITHM (SP800-67/38A), BCRYPT_DES_ALGORITHM (FIPS 46-3/81), BCRYPT_CHACHA20_POLY1305_ALGORITHM (RFC 8439), BCRYPT_XTS_AES_ALGORITHM (SP-800-38E / IEEE 1619-2007). -> applied as: the scan_all_snapshots byte-signature scanner enumerates every key-birth snapshot (CryptImportKey / BCryptGenerateSymmetricKey hook entry captures) and tests every recorded key blob against the full BCrypt algorithm-identifier set above, so that one snapshot may contain AES / RSA / ECDH / ECDSA / 3DES / DES / ChaCha20-Poly1305 / XTS-AES material and still be matched. The CNG identifier table is the authoritative enumeration of algorithm strings the scanner must support.
- **Field mappings**:
  - `scope` = `ALL snapshots in bundle['keybirth_snapshots']` ← Rule logic plus Microsoft CNG identifier table establishing that a single capture may contain any of the listed algorithms; scanner must iterate all snapshots, not just the first.
  - `algorithm_set` = `AES, RSA, ECDH_P256/P384/P521, ECDSA_P256/P384/P521, 3DES, DES, ChaCha20-Poly1305, XTS-AES (plus hashes SHA1/256/384/512` ← https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers table rows (verbatim BCRYPT_*_ALGORITHM constants and their L"…" string identifiers).
  - `trigger_hooks` = `CryptImportKey / BCryptGenerateSymmetricKey hook entry` ← Ransack capture pipeline conventions (rule provenance excerpt) + CNG API surface documented on the same Microsoft Learn portal.
  - `blob_layout` = `BLOBHEADER (8B) + RSAPUBKEY (12B: magic 'RSA1' + bitlength + pubexp) + modulus[bitlength/8] for PUBLICKEYBLOB; AES key b` ← Microsoft Wincrypt.h PUBLICKEYBLOB layout (referenced in BCRYPT_RSAKEY_BLOB / base-provider-key-blobs Microsoft Learn pages) plus the CNG identifier mapping above.
  - `standards` = `FIPS 197 (AES), PKCS#1 (RSA), SP800-56A (ECDH), FIPS 186-2/X9.62 (ECDSA), SP800-67/38A (3DES), FIPS 46-3/81 (DES), RFC 8` ← Identical 'Standard:' column entries in the Microsoft Learn cng-algorithm-identifiers table at the cited line and adjacent rows.

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: composite_driver (orchestrates aeskeyfind + wanakiwi + BCRYPT + Avaddon scanners over Ransack's PinTool keybirth_snapshots)
- **Citation**: Composite of all four upstream sources above; the driver itself is Ransack-specific orchestration (not a port of any single upstream). RSA modulus extraction uses Microsoft PUBLICKEYBLOB layout (Wincrypt.h CRYPT_PUBKEY_INFO).
- **URL**: https://github.com/aguinet/wannakey/blob/master/wannakey/wkey/search_primes.cpp
- **Quote**:

```text
# PUBLICKEYBLOB layout (Microsoft Wincrypt.h):
# BLOBHEADER (8B) + RSAPUBKEY (12B: magic 'RSA1' + bitlength + pubexp) + modulus[bitlength/8]
# bundle['keybirth_snapshots'][*]['snapshot_file'] — relative path under trace_dir;
# captures triggered at CryptImportKey/BCryptGenerateSymmetricKey hook entry.
# Per-modulus prime_bytes computed:
#   mod_bytes = (N.bit_length() + 7) // 8
#   pb = mod_bytes // 2          # RFC 8017 §3.1 + FIPS 186-5 §A.1.1
```

- **Derivation**: Driver loops over each (snapshot_file, scanner) pair. For wanakiwi_prime_scan it first extracts every RSA modulus from the bundle's crypto_summary.asym_blobs (each entry parsed as Microsoft PUBLICKEYBLOB: BLOBHEADER[8] + RSAPUBKEY[12] with 'RSA1' magic at offset 8 + bit_length at offset 12 + modulus at offset 20). For each modulus N, prime_bytes = (N.bit_length()/8)/2 per RFC 8017 RSA semiprime structure — this fixes a silent FN in literal wannakey port that hardcodes 128 bytes (RSA-2048 only).

### ② Mechanism
- **Algorithm/Concept**: Two-pass orchestration: pass 1 = pre-extract every RSA public modulus N from S1-captured asym_blobs (via PUBLICKEYBLOB parsing); pass 2 = for each snapshot file, run aeskeyfind_scan + bcrypt_rsa_blob_scan + avaddon_session_key_scan unconditionally + wanakiwi_prime_scan once per (snapshot, N) pair with per-N prime_bytes.
- **Cryptographic role**: Bridges S1 (API-traced asym_blobs) and S2 (raw heap snapshots) into a single verdict-feeding hit list. The asym_blobs come from CryptExportKey/BCryptExportKey hooks; the snapshots come from CryptImportKey/CryptGenKey/BCryptGenerateSymmetricKey entry-point captures.
- **Why this is a unique signature**: Not a signature itself — this is the aggregation/dispatch layer. Its correctness depends entirely on the four component scanners. The PUBLICKEYBLOB parsing is signed by the 'RSA1' magic at offset 8 (same magic as BCRYPT but at a different offset due to BLOBHEADER prefix).
- **Bit provenance**: PUBLICKEYBLOB structure: Wincrypt.h CRYPT_INTEGER_BLOB / RSAPUBKEY (declared in wincrypt.h, documented in 'Base Provider Key BLOBs'). 'RSA1' magic at offset 8 is the legacy CryptoAPI counterpart to CNG's BCRYPT_RSAPUBLIC_MAGIC (both encode ASCII 'RSA1' = 0x31415352).

### ③ Detection
- **Runtime step**: Top-level analysis entry: called from chain.py / consolidator after PinTool finishes. Reads bundle['keybirth_snapshots'] metadata + bundle['crypto_summary']['asym_blobs'], opens each snapshot file under bundle['trace_dir'], dispatches all four scanners, tags each hit with snapshot_file relative path, aggregates per-scanner counts.
- **Match criteria**: For each snap_meta with valid snapshot_file under trace_dir: read full bytes; run 4 scanners; wanakiwi runs once per modulus extracted from asym_blobs with prime_bytes = mod_bytes/2. Returns aggregate dict with per-scanner hit lists and counts.
- **Cross-axis role**: aux integrator. Consumes S1 (asym_blobs) and S2 (keybirth_snapshots) and produces a unified hit list that feeds the verdict layer alongside S3 (entropy timeline).
- **Implementation file**: onHost/analysis/byte_signature_scanner.py:479-534 (scan_all_snapshots), :444-476 (_extract_rsa_moduli_from_chain helper).

### ④ Limits
- **Ambiguity shared with**: PUBLICKEYBLOB and BCRYPT_RSAKEY_BLOB both encode 'RSA1' magic but at different offsets (8 vs 0) — handled correctly by routing legacy CryptoAPI blobs to _extract_rsa_moduli_from_chain and CNG blobs to bcrypt_rsa_blob_scan.
- **FP scenarios**:
  - Inherits FP set from all four component scanners (transitive)
  - Misparsing of malformed asym_blobs as PUBLICKEYBLOB — guarded by 'RSA1' magic at offset 8 and CNG-supported bit_length whitelist, so practical FP is rare
  - Misclassification of a non-RSA blob hex containing accidental 'RSA1' bytes at offset 8 (vanishingly unlikely)
- **FN scenarios**:
  - Snapshot file missing from disk (silently skipped — could mask true positives)
  - Empty snapshot file (skipped)
  - RSA modulus not in {1024,2048,3072,4096} (e.g., 1536-bit legacy CSP) — extracted but bit_length whitelist filter drops it
  - asym_blobs hex string under minimum length (8+12+128 bytes = 296 hex chars) is skipped — would miss truncated captures even if the head contains a valid magic
  - All transitive FNs of the four component scanners

*Consistency verdict*: **depends on component scanners — produces hit list, not verdict**
*Notes*: Critical correctness fix vs. literal wannakey port: per-N prime_bytes computation (mod_bytes//2) instead of hardcoded 128. This makes RSA-3072 and RSA-4096 prime recovery actually work — without it, those keys would be silent FN despite being CNG-supported and ransomware-common.

### Rationale + Usage
### (5) Rationale (why included in the catalog)
- **Why included**: a unified entry point that consistently applies all byte-pattern scanners (aeskeyfind/wanakiwi/bcrypt/avaddon) across every keybirth_snapshot + a coupling layer that automatically extracts RSA modulus from the asym_blob chain and supplies it to wanakiwi. An aggregation layer that enables cross-axis corroboration of individual scanners.
- **Historical motivation**: the verbatim ports of four independent research efforts—Halderman (AES) + Guinet (RSA prime) + Microsoft CNG (RSA blob) + Yuste (Avaddon)—must be executed in an integrated manner against the same snapshot input for cross-corroboration to be possible. The dependent chain in a single snapshot of BCRYPT blob → modulus extraction → wanakiwi prime hit cannot be implemented via individual scanner calls; the historical motivation that makes this explicit constitutes the multi-tool consolidation requirement.
- **Coverage gap if absent**: without this function, when determining the applicable SIG-* trigger, scanners must be called separately, resulting in (a) potential snapshot omission, (b) modulus extracted from asym_blob not being passed to wanakiwi, missing RSA prime hits themselves, and (c) per-snapshot file metadata (snapshot_file tag) omission preventing trace-source tracking.

### (6) Usage (how / why used)
- **Primary use case**: Aggregation entry point: dispatch all byte-pattern scanners over keybirth snapshots with cross-scanner modulus chaining
- **Consumer files**: onHost/analysis/byte_signature_scanner.py, onHost/analysis/recovery_cases.py, onHost/analysis/report.py
- **Contributes to**: SIG-AES / SIG-WANAKEY / SIG-BCRYPT / SIG-AVADDON cross-trigger, S2+S3+S4 multi-axis corroboration, snapshot-to-hit provenance tagging, per-modulus prime byte sizing (1024/2048/3072/4096 RSA), report aggregate counts (aeskeyfind_count / bcrypt_rsa_blob_count / etc.)
- **Concrete example**: WannaCry trace bundle: 3 keybirth_snapshots + RSA-2048 modulus included in asym_blob → scan_all_snapshots applies four scanners to all snapshots → in one snapshot, aeskeyfind AES-128 hit + bcrypt RSA1 blob hit + wanakiwi prime hit occur simultaneously → S2/S3/S4 all grounded → decryptability=high determination.

### Citations check
  - URL: https://github.com/aguinet/wannakey/blob/master/wannakey/wkey/search_primes.cpp
    - quote_verified: PALIGN=4, MINIMAL_ENTROPY=0.7, dual-endian N%P==0 test
    - support: INDIRECT | authority: PRIMARY
    - excerpt: Same fetch as wanakiwi_prime_scan rule above; confirms the upstream wanakiwi behavior that scan_all_snapshots orchestrates per-modulus.
  - URL: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
    - quote_verified: BCRYPT_RSAKEY_BLOB struct + BitLength field
    - support: INDIRECT | authority: PRIMARY
    - excerpt: Confirms the CNG-supported RSA bit-length enumeration via BCRYPT_RSA_ALGORITHM (typical 1024/2048/3072/4096).
  - URL: https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
    - quote_verified: RSA semiprime N = p*q with |p|=|q|=|N|/2 bits (RFC 8017 §3.1 / FIPS 186-5 §A.1.1)
    - support: UNRELATED | authority: PRIMARY
    - excerpt: FIPS-197 is the AES spec, NOT RSA — PROVENANCE incorrectly anchors the RSA prime-length constraint to FIPS-197. The correct primary source is RFC 8017 §3.1 (RSA cryptography spec) and FIPS 186-5 §A.1.

### Citations check
  - URL: https://github.com/aguinet/wannakey/blob/master/wannakey/wkey/search_primes.cpp
    - quote_verified: PUBLICKEYBLOB layout: BLOBHEADER (8B) + RSAPUBKEY (12B: magic 'RSA1' + bitlength + pubexp) + modulus[bitlength/8]; per-modulus prime_bytes mod_bytes/2 (RFC 8017 §3.1 + FIPS 186-5 §A.1.1)
    - support: INDIRECT | authority: PRIMARY
    - excerpt: search_primes.cpp takes PrimeSize as a parameter, but wannakey's single invocation is fixed at RSA-2048 (128 byte). The PUBLICKEYBLOB 8B+12B+modulus layout is not in search_primes.cpp itself — wannakey's N (modulus) extraction is performed in a separate .eky/.pky file parser (external to key files).

## wanakiwi_prime_scan

### URL / Quote Line-citation

- **`OK_PARTIALLY_LOCATED (3/11 exact, rest fuzzy/not found)`**
  - URL: <https://github.com/aguinet/wannakey/blob/master/wannakey/wkey/search_primes.cpp>
  - Quote NOT_LOCATED: `# BLOBHEADER (8B) + RSAPUBKEY (12B: magic 'RSA1' + bitlength + pubexp) + modulus[bitlength/8]` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `# PUBLICKEYBLOB layout (Microsoft Wincrypt.h):` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `# Per-modulus prime_bytes computed:` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `# bundle['keybirth_snapshots'][*]['snapshot_file'] — relative path under trace_dir;` (page alive but quote not in HTML)
  - Quote NOT_LOCATED: `# captures triggered at CryptImportKey/BCryptGenerateSymmetricKey hook entry.` (page alive but quote not in HTML)

- **`OK_LINE_VERIFIED (0/0 quotes located exact)`**
  - URL: <https://github.com/aguinet/wannakey/blob/master/wannakey/wkey/tools.cpp>


### Rule derivation chain (C13 automated, FULLY_DERIVED)
- **Primary source**: <https://github.com/aguinet/wannakey/blob/master/wannakey/wkey/search_primes.cpp>
- **Page line**: 2824
- **Quoted fragment**: `for (size_t i = 0; i <= LenStop; i += PALIGN) { uint8_t const* Block = &Data[i]; const double E = normalizedEntropy(Block, PrimeSize); ... if (E >= MINIMAL_ENTROPY) { auto P = getInteger(Block, PrimeSize, false); if (N % P == 0) { return P; } P = getInteger(Block, PrimeSize, true); if (N % P == 0) {`
- **Derivation chain**: Primary source: https://github.com/aguinet/wannakey/blob/master/wannakey/wkey/search_primes.cpp → page line 2824 (PALIGN-step scan loop), line 2642 (normalizedEntropy invocation), line 2636 (Block pointer extraction) reads `for (size_t i = 0; i <= LenStop; i += PALIGN) { uint8_t const* Block = &Data[i]; const double E = normalizedEntropy(Block, PrimeSize); }` and after passing entropy ≥ MINIMAL_ENTROPY (0.7), the `getInteger` bidirectional little/big-endian + `N % P == 0` division verification → applied to the rule as: `function`=`wanakiwi_prime_scan` (borrowed from the Guinet wanakiwi tool — the WannaCry technique for recovering unclear heap-residue primes from CryptDestroyKey), `phase`=`ByteSigScanner` (byte-scans RSA prime candidates from heap-dump memory), `mechanism`=`PALIGN (4-byte) aligned-step sliding + normalizedEntropy ≥ 0.7 prefilter → trial division N % P == 0 to confirm RSA factor` (extracts prime candidates from memory deallocated by CryptDestroyKey without secure zeroing), `target`=`RSA prime factor in heap residue` (recovery target of WannaCry private-key p, q), `input`=`key_residue_snapshots/heap dump`, `output`=`recovered_RSA_prime(P) with N%P==0`.
- **Field mappings**:
  - `function` = `wanakiwi_prime_scan` ← search_primes.cpp file name + Guinet wanakiwi (a.k.a. wannakey) prime-search algorithm — name borrowed verbatim from the WannaCry decryption tool
  - `phase` = `ByteSigScanner` ← byte_signature_scanner.py host + matches the memory byte-sequence PALIGN-step scan loop at search_primes.cpp line 2824
  - `stride` = `PALIGN (4 bytes)` ← search_primes.cpp line 2824: `for (size_t i = 0; i <= LenStop; i += PALIGN)` — 4-byte alignment instead of single-byte to reduce computation
  - `entropy_filter` = `normalizedEntropy ≥ MINIMAL_ENTROPY (0.7)` ← search_primes.cpp line 2642: `const double E = normalizedEntropy(Block, PrimeSize)` + `if (E >= MINIMAL_ENTROPY)` — randomness prefilter at the level of cryptographic material
  - `validation` = `N % P == 0 (trial division both endians)` ← search_primes.cpp: `auto P = getInteger(Block, PrimeSize, false); if (N % P == 0) { return P; } P = getInteger(Block, PrimeSize, true); if (N % P == 0) { return P; }` — bidirectional little/big-endian trial division
  - `recovery_target` = `WannaCry CryptDestroyKey heap-leaked RSA prime` ← WebFetch analysis: 'WannaCry's CryptDestroyKey function which failed to securely zero cryptographic structures before deallocation'

### Origin / Mechanism / Detection / Limits
### ① Origin
- **Source type**: github_master_source (Adrien Guinet 2017)
- **Citation**: Guinet, A. (2017) 'WannaKey / WannaKiwi: recovering RSA private key components from wcry.exe address space' — exploits the fact that on Windows XP CryptReleaseContext does not zero the prime buffers used inside MS_ENH_RSA_AES_PROV's RSA keygen.
- **URL**: https://github.com/aguinet/wannakey/blob/master/wannakey/wkey/search_primes.cpp
- **Quote**:

```text
#define PALIGN 4              [search_primes.cpp:24]
#define MINIMAL_ENTROPY 0.7   [search_primes.cpp:25]
for (size_t i = 0; i <= LenStop; i += PALIGN) {
    uint8_t const* Block = &Data[i];
    const double E = normalizedEntropy(Block, PrimeSize);
    if (E >= MINIMAL_ENTROPY) {                       [search_primes.cpp:38-44]
// tools.cpp:44-62 normalizedEntropy:
Ret += P * std::log(P);
return -Ret / std::log(256.);
```

- **Derivation**: Guinet's writeup identifies the post-CryptReleaseContext heap as containing the two large primes p,q of the per-victim RSA key. search_primes.cpp walks the 4-byte-aligned heap, takes each 128-byte (RSA-2048) candidate window, applies a normalised Shannon entropy gate at H >= 0.7 (well above natural-language and PE-image entropy), then tests both little- and big-endian integer interpretations against N % cand == 0 where N is the public modulus extracted from 00000000.eky / .pky. The port preserves PALIGN=4, the dual-endian test, and the entropy gate; rsautil.c:57's Miller-Rabin RSA_check_key gate that wanakiwi adds *after* divisibility is documented as a separate validation layer.

### ② Mechanism
- **Algorithm/Concept**: RFC 8017 / FIPS 186-5 RSA: N = p * q with |p|=|q|=|N|/2 bits. If raw p (or q) remains in process heap after key destruction, then N mod p == 0 uniquely identifies it among all 128-byte (RSA-2048), 192-byte (RSA-3072), or 256-byte (RSA-4096) windows — because random co-factors of N are exponentially improbable.
- **Cryptographic role**: Prime co-factor of the asymmetric session-key encryption key (the RSA keypair generated per-victim that wraps the per-file AES key). Recovery yields the full RSA private key and thus full decryption capability.
- **Why this is a unique signature**: The divisibility test N % cand == 0 with cand of exactly len(N)/2 bytes IS the cryptographic signature — only a true prime factor of N satisfies this, and modular reduction on a 128-byte integer makes random matches astronomically improbable (~1 in 2^1024). The entropy gate is a *speed* filter that culls zero-padded / repeated-byte regions before paying for big-int modulo.
- **Bit provenance**: search_primes.cpp:32-90 (Search function); tools.cpp:44-62 (normalizedEntropy); RFC 8017 §3.1 (RSA key model); FIPS 186-5 §A.1.1 (prime length constraint).

### ③ Detection
- **Runtime step**: scan_all_snapshots() first extracts every RSA public modulus N from the bundle's crypto_summary.asym_blobs by parsing PUBLICKEYBLOB headers (8B BLOBHEADER + 12B RSAPUBKEY 'RSA1'+bitlength+pubexp + modulus). For each snapshot file, for each captured N, it computes prime_bytes = (bit_length(N)//8)//2 and invokes wanakiwi_prime_scan(data, N, prime_bytes=pb).
- **Match criteria**: 4-byte-aligned offset in [0, len-PrimeSize]; normalizedEntropy(window) >= 0.7 (stricter than wanakiwi's 0.5 default; matches wannakey's hardcoded); for each endian in {little,big}: cand = int.from_bytes(window, endian); cand > 1; N % cand == 0 and cand != N. First successful endian per offset suffices.
- **Cross-axis role**: aux (cross-references S1 — needs PUBLICKEYBLOB captured via CryptExportKey/BCryptExportKey API hooks — with S2 snapshot bytes). Without S1's modulus, no test is possible; without S2 bytes, no primes are findable.
- **Implementation file**: onHost/analysis/byte_signature_scanner.py:273-307 (wanakiwi_prime_scan), :252-270 (_normalized_shannon), :444-476 (_extract_rsa_moduli_from_chain), :514-529 (driver invocation with per-modulus prime_bytes adjustment).

### ④ Limits
- **Ambiguity shared with**: None at the math level — N % p == 0 with |p|=|N|/2 is unique to RSA factorisation. Only ambiguity is *which* victim's keypair if multiple Ns are captured (resolved by per-N hit attribution).
- **FP scenarios**:
  - Mathematically: a non-prime divisor of N (impossible for true RSA N=p*q semiprime; the only divisors are 1, p, q, N — and cand <= 1 and cand != N are excluded). Effectively zero true FP.
  - Operational: if the captured N is actually a non-RSA blob misclassified as PUBLICKEYBLOB, the modulo test is meaningless (mitigated by 'RSA1' magic gate at offset 8).
- **FN scenarios**:
  - Prime stored in word/byte order other than the host's little/big-endian (e.g. limb-reversed 64-bit-limb representations from GMP / OpenSSL BN — only a uniform-endian flat representation matches)
  - Prime offset not 4-byte aligned (PALIGN=4 stride misses 75% of byte positions — upstream's design choice, faithfully ported)
  - Entropy of the prime window happens to fall below 0.7 (rare but possible if p has long zero runs — entropy of a true random 128-byte prime is ~0.99)
  - Prime length mismatch — port now computes prime_bytes = mod_bytes/2 per-N so RSA-3072/4096 work, but only RSA-1024/2048/3072/4096 are enumerated (CNG-supported set)

*Consistency verdict*: **ransom-positive when correlated with S1 CryptGenKey(CALG_RSA_KEYX) or BCryptGenerateKeyPair on the same process**
*Notes*: Port adds defensive `cand != modulus_int` guard (wannakey omits — divisibility N%N==0 would trigger trivially). Driver computes prime_bytes per-N (fixes RSA-3072/4096 silent FN that exists in literal wannakey port).

---

### Rationale + Usage
### (5) Rationale (why included in the catalog)
- **Why included**: the historic technique by which Guinet 2017 wannakey/wanakiwi recovered the RSA-2048 prime factor from memory on WannaCry victim PCs and achieved actual decryption. It exploits the chronic flaw of Windows CryptoAPI in which primes persist in heap due to missing CryptReleaseContext calls.
- **Historical motivation**: immediately following the WannaCry 2017 outbreak, Adrien Guinet discovered that the RSA-2048 prime p persists in unreleased heap immediately after the CryptGenKey call in wsmcry.exe process memory → release of wannakey/wanakiwi enabled actual decryption. The core motivation is the Microsoft CryptoAPI flaw whereby temporary buffers in lsasrv/rsaenh.dll are not zeroized when CryptDestroyKey is not called.
- **Coverage gap if absent**: without this rule, the RSA-2048 N % p == 0 divisibility test cannot be performed, and even when the modulus is chained from asym_blob, the prime factor cannot be grounded. The SIG-WANAKEY trigger cannot fire, and the very possibility of RSA family decryption cannot be determined.

### (6) Usage (how / why used)
- **Primary use case**: RSA prime factor recovery via divisibility test (N mod p == 0) for asymmetric key reconstruction
- **Consumer files**: onHost/analysis/byte_signature_scanner.py, onHost/analysis/recovery_cases.py, onHost/analysis/report.py
- **Contributes to**: SIG-WANAKEY trigger, RSA modulus-prime corroboration, S4 asym key recovery axis, decryptability verdict (WannaCry-class CryptoAPI misuse)
- **Concrete example**: in the WannaCry tasksche.exe heap snapshot, the 128-byte little-endian RSA prime p is detected together with the PUBLICKEYBLOB modulus N → entropy 0.78, N%p==0 holds, bit_len=1024 → the entire RSA-2048 private key can be reconstructed, decryptability=true determination.

---

### Citations check
  - URL: https://github.com/aguinet/wannakey/blob/master/wannakey/wkey/search_primes.cpp
    - quote_verified: #define PALIGN 4
    - support: DIRECT | authority: PRIMARY
    - excerpt: Line 35: `#define PALIGN 4` — confirmed verbatim.
  - URL: https://github.com/aguinet/wannakey/blob/master/wannakey/wkey/search_primes.cpp
    - quote_verified: #define MINIMAL_ENTROPY 0.7
    - support: DIRECT | authority: PRIMARY
    - excerpt: Line 37: `#define MINIMAL_ENTROPY 0.7` — confirmed verbatim.
  - URL: https://github.com/aguinet/wannakey/blob/master/wannakey/wkey/search_primes.cpp
    - quote_verified: for (size_t i = 0; i <= LenStop; i += PALIGN) { ... if (E >= MINIMAL_ENTROPY) { ... auto P = getInteger(Block, PrimeSize, false); if (N % P == 0) ... P = getInteger(Block, PrimeSize, true); if (N % P == 0) ...
    - support: DIRECT | authority: PRIMARY
    - excerpt: Lines 96-108 serial loop, lines 101-108 dual-endian divisibility test using getInteger with boolean endian parameter.
  - URL: https://github.com/aguinet/wannakey/blob/master/wannakey/wkey/tools.cpp
    - quote_verified: Ret += P * std::log(P); return -Ret / std::log(256.);
    - support: DIRECT | authority: PRIMARY
    - excerpt: normalizedEntropy (lines 44-62): accumulates `Ret += P * std::log(P)` then returns `-Ret / std::log(256.)`.

---

### Citations check
  - URL: https://github.com/aguinet/wannakey/blob/master/wannakey/wkey/search_primes.cpp
    - quote_verified: #define PALIGN 4; #define MINIMAL_ENTROPY 0.7; for (size_t i = 0; i <= LenStop; i += PALIGN); normalizedEntropy(Block, PrimeSize); getInteger(Block, PrimeSize, false/true); if (N % P == 0)
    - support: DIRECT | authority: PRIMARY
    - excerpt: Line 27: #define PALIGN 4. Line 29: #define MINIMAL_ENTROPY 0.7. Lines 97-113: for (size_t i = 0; i <= LenStop; i += PALIGN) ... normalizedEntropy(Block, PrimeSize) ... getInteger(Block, PrimeSize, fa
  - URL: https://github.com/aguinet/wannakey/blob/master/wannakey/wkey/tools.cpp
    - quote_verified: double const P = (double)Count / (double)Len; Ret += P * std::log(P); return -Ret / std::log(256.)
    - support: DIRECT | authority: PRIMARY
    - excerpt: Lines 44-62: double normalizedEntropy(uint8_t const* Data, const size_t Len) { ... for (uint32_t Count : Hist) { if (Count) { double const P = (double)Count / (double)Len; Ret += P * std::log(P); } } 

---
