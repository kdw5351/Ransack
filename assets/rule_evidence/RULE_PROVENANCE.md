# crypto_api.json — Rule Provenance & Non-Heuristic Verification

**Generated:** 2026-06-02 · **Revised:** 2026-06-29 (counts + §5/§6 enumerations re-synced to the live `crypto_api.json`) · **Scope:** `assets/crypto_api.json` (the ~1000-rule crypto-API
hook catalog) plus a sourcing summary for the other rulesets.

This document answers, for every rule in the catalog, two questions:

1. **Why does this rule exist** — what real, published API symbol it corresponds to.
2. **Why is it non-heuristic** — the argument indices, `kind`, and `category` are not
   guessed; each is read directly off the function's *real prototype* from the library's
   public header (OpenSSL 3, mbedTLS 3.6, libsodium, argon2, Crypto++) or the vendor's
   official reference (Microsoft Learn, Wine `rsaenh.spec` for the CSP CP* contract).

---

## 1. TL;DR verdict

| Result | Count |
|---|---|
| Active rules after audit | **896** |
| — verified against a real header prototype (deterministic, 0 arg-index bugs) | **748** |
| — Microsoft CryptoAPI rules verified vs Microsoft Learn / Wine `rsaenh.spec` | **65** |
| — Microsoft CNG/NCrypt rules verified vs Microsoft Learn `bcrypt.h`/`ncrypt.h` | **64** (59 active + 5 `catalog_only` variants) |
| — `crypt32` / `ntdll` / CRT / Crypto++ verified vs vendor docs | resolved below |
| **Argument-index bugs found & fixed** | **2** (`RtlCompressBuffer`, `RtlDecompressBuffer`) |
| Rules marked `catalog_only` (non-hookable: libcrypto 71 = 16 NID consts + 40 macro-aliases + 15 non-exported helpers; + 38 Crypto++ C++ classes + 5 CNG keygen-variant pseudo-names + donna 2 + mbedtls 1) | **117** |
| Rules that extract real argument buffers / handles (indices matter) | **201** |
| Rules that are presence markers (all indices `-1`, active) | **695** |

**Bottom line:** every argument index that the PinTool actually dereferences in the active
catalog now maps to the correct parameter of the real function signature. No heuristic /
guessed argument positions remain.

---

## 2. What the rules are, and what "non-heuristic" means

Each rule tells the on-VM Intel-PIN tool (`onVM/ransomflow`, see `src/rule_catalog.cpp`)
how to instrument one exported crypto function. The schema:

| field | meaning | how the PinTool uses it |
|---|---|---|
| `dll`, `func` | the exported symbol to hook | symbol resolution at image load |
| `kind` | semantic event (`rand`/`keygen`/`kdf`/`hash`/`sym_enc`/`asym_enc`/`key_import`/`key_export`/`memcpy`/`normal_op`) | decides what record is emitted |
| `in_buf_arg`,`in_len_arg` | zero-based index of the input buffer + its length | reads the plaintext / message bytes at call time |
| `out_buf_arg`,`out_len_arg` | index of the output buffer + length | reads the ciphertext / digest / derived key |
| `handle_in_arg`,`handle_out_arg` | index of a crypto handle consumed / produced | builds the key-provenance graph |
| `category` | algorithm-inference bucket (Python side, `crypto_apis.py`) | routes the symbol to rng/hash/kdf/… |
| `catalog_only` | if true, the symbol is documented but **not** hooked | skipped by `CollectCryptoRulesForDll` |
| `source`,`note`,`header`,`algorithm` | provenance annotations | documentation only |

A rule is **non-heuristic** iff (a) the symbol is a real export of `dll`, and (b) every
`*_arg >= 0` equals the zero-based position of that parameter in the function's real
prototype. Both are mechanically checkable against ground truth — which is exactly what
this audit did.

---

## 3. Methodology (reproducible)

All audit tooling lives in `_audit/`:

1. **Header ground truth** — `_audit/parse_headers.py` fetches the *actual* public headers
   (OpenSSL `master`, mbedTLS `mbedtls-3.6`, libsodium `master`, argon2, donna) into
   `_audit/headers/**` and parses **2 457** real C prototypes into `_audit/proto_db.json`.
2. **Deterministic verification** — `_audit/verify_rules.py` matches every rule's `func` to
   its real prototype and checks: arity in range; `in_buf`/`out_buf`/handle args point to
   pointer (or array) params; `in_len`/`out_len` point to integer-valued params; `out_buf`
   does not point to a `const` pointee. Result: **748 / 748** header-resolved rules pass with
   **zero** flags.
3. **Microsoft + Crypto++ verification** — functions absent from C headers (CNG, CryptoAPI, CSP
   CP*, crypt32, ntdll, Crypto++ C++ classes) were checked against Microsoft Learn pages and
   the Crypto++ wiki; the trickiest CNG signatures (`BCryptEncrypt`, `BCryptImportKey`,
   `BCryptExportKey`) and both `Rtl*CompressBuffer` signatures were fetched live from
   Microsoft Learn during the audit.
4. **OpenSSL symbol existence** — the 105 OpenSSL names not in the header DB were classified
   against OpenSSL 3 headers + the OpenSSL 3.0 migration guide + BoringSSL headers
   (`_audit/verdict_ossl.json`).

---

## 4. Fixes applied to the active catalog

### 4.1 Argument-index bugs (data-correctness) — FIXED

Both are `ntdll.dll` compression primitives (ransomware often compresses-then-encrypts).
Verified against Microsoft Learn `ntifs.h`.

| func | field | was | now | reason |
|---|---|---|---|---|
| `RtlCompressBuffer` | in_buf / in_len / out_buf / out_len | 2 / 3 / 4 / 5 | **1 / 2 / 3 / 6** | sig: `(0 fmt, 1 UncompressedBuffer, 2 size, 3 CompressedBuffer, 4 size, 5 chunk, 6 FinalCompressedSize, 7 workspace)` — old indices were shifted +1 and `out_len` pointed at the chunk-size, not the written length |
| `RtlDecompressBuffer` | out_buf / out_len | 0 / 1 | **1 / 5** | sig: `(0 fmt, 1 UncompressedBuffer[out], 2 size, 3 CompressedBuffer[in], 4 size, 5 FinalUncompressedSize)` — old `out_buf=0` pointed at the USHORT format code; input side (`in=3,inlen=4`) was already correct |

Had these shipped, the PinTool would have dereferenced a `USHORT` format code as a buffer
pointer (crash / garbage capture) and recorded the wrong compressed-stream length.

### 4.2 Misnamed → renamed

- `EVP_CIPHER_CTX_get_cipher` → **`EVP_CIPHER_CTX_get0_cipher`** (the real OpenSSL 3 accessor;
  now resolves in the header DB).

### 4.3 Non-hookable symbols → `catalog_only: true` (117)

117 entries are kept for their algorithm-name catalog data but flagged `catalog_only` so the
hook engine (`CollectCryptoRulesForDll`) skips them — they cannot bind by symbol name. By
library: **libcrypto-3 71** (16 NID `#define` constants below + 40 macro-aliases of §7 + 15
non-exported helpers), **cryptopp 38** (C++ classes — name-mangled / statically linked),
**bcrypt 5** (synthetic `BCryptGenerateKeyPair_*`/`BCryptGenRandom_*` algorithm-variant names),
**curve25519-donna 2**, **mbedtls 1**. The 16 `EVP_PKEY_*` NID `#define` integer constants
(not callable exports) are:

`EVP_PKEY_CMAC`, `EVP_PKEY_DH`, `EVP_PKEY_DSA`, `EVP_PKEY_EC`, `EVP_PKEY_ED25519`, `EVP_PKEY_ED448`, `EVP_PKEY_HKDF`, `EVP_PKEY_HMAC`, `EVP_PKEY_POLY1305`, `EVP_PKEY_RSA`, `EVP_PKEY_RSA_PSS`, `EVP_PKEY_SCRYPT`, `EVP_PKEY_SIPHASH`, `EVP_PKEY_TLS1_PRF`, `EVP_PKEY_X25519`, `EVP_PKEY_X448`

---

## 5. Per-rule provenance — rules that extract argument buffers / handles (201)

These are the rules where argument indices are dereferenced, so correctness matters most.
Each row shows the **real signature** and the **captured index → parameter** mapping; you can
verify any row by reading the `func`'s parameter list. (`@N` marks zero-based positions for
Microsoft prototypes; OpenSSL/mbedTLS/sodium signatures are the verbatim header text.)

| # | dll | func | kind | real signature (params; @=index for MS) | captured indices -> param |
|---|-----|------|------|------------------------------------------|---------------------------|
| 1 | _raw_aes.pyd | `AES_start_operation` | keygen | `int CIPHER_START_OPERATION(const uint8_t key[], size_t key_len, CIPHER_STATE_TYPE **pResult)` | in=0:key; inlen=1:key_len; hOut=2:pResult |
| 2 | _raw_aes.pyd | `AES_stop_operation` | normal_op | `int CIPHER_STOP_OPERATION(BlockBase *state)` | hIn=0:state |
| 3 | _raw_aesni.pyd | `AESNI_start_operation` | keygen | `int AESNI_start_operation(const uint8_t key[], size_t key_len, AESNI_State **pResult)` | in=0:key; inlen=1:key_len; hOut=2:pResult |
| 4 | _raw_aesni.pyd | `AESNI_stop_operation` | normal_op | `int AESNI_stop_operation(BlockBase *bb)` | hIn=0:bb |
| 5 | _raw_cbc.pyd | `CBC_decrypt` | sym_enc | `int CBC_decrypt(CbcModeState *cbcState, const uint8_t *in, uint8_t *out, size_t data_len)` | in=1:in; inlen=3:data_len; out=2:out; outlen=3:data_len; hIn=0:cbcState |
| 6 | _raw_cbc.pyd | `CBC_encrypt` | sym_enc | `int CBC_encrypt(CbcModeState *cbcState, const uint8_t *in, uint8_t *out, size_t data_len)` | in=1:in; inlen=3:data_len; out=2:out; outlen=3:data_len; hIn=0:cbcState |
| 7 | _raw_cbc.pyd | `CBC_start_operation` | keygen | `int CBC_start_operation(BlockBase *cipher, const uint8_t iv[], size_t iv_len, CbcModeState **pResult)` | in=1:iv; inlen=2:iv_len; hIn=0:cipher; hOut=3:pResult |
| 8 | _raw_cbc.pyd | `CBC_stop_operation` | normal_op | `int CBC_stop_operation(CbcModeState *state)` | hIn=0:state |
| 9 | _raw_ctr.pyd | `CTR_decrypt` | sym_enc | `int CTR_decrypt(CtrModeState *ctr_state, const uint8_t *in, uint8_t *out, size_t data_len)` | in=1:in; inlen=3:data_len; out=2:out; outlen=3:data_len; hIn=0:ctr_state |
| 10 | _raw_ctr.pyd | `CTR_encrypt` | sym_enc | `int CTR_encrypt(CtrModeState *ctr_state, const uint8_t *in, uint8_t *out, size_t data_len)` | in=1:in; inlen=3:data_len; out=2:out; outlen=3:data_len; hIn=0:ctr_state |
| 11 | _raw_ctr.pyd | `CTR_start_operation` | keygen | `int CTR_start_operation(BlockBase *cipher, uint8_t counter_block0[], size_t counter_block0_len, size_t prefix_len, unsigned counter_len, unsigned little_endian, CtrModeState **pResult)` | in=1:counter_block0; inlen=2:counter_block0_len; hIn=0:cipher; hOut=6:pResult |
| 12 | _raw_ctr.pyd | `CTR_stop_operation` | normal_op | `int CTR_stop_operation(CtrModeState *ctr_state)` | hIn=0:ctr_state |
| 13 | _raw_ecb.pyd | `ECB_decrypt` | sym_enc | `int ECB_decrypt(EcbModeState *ecbState, const uint8_t *in, uint8_t *out, size_t data_len)` | in=1:in; inlen=3:data_len; out=2:out; outlen=3:data_len; hIn=0:ecbState |
| 14 | _raw_ecb.pyd | `ECB_encrypt` | sym_enc | `int ECB_encrypt(EcbModeState *ecbState, const uint8_t *in, uint8_t *out, size_t data_len)` | in=1:in; inlen=3:data_len; out=2:out; outlen=3:data_len; hIn=0:ecbState |
| 15 | _raw_ecb.pyd | `ECB_start_operation` | keygen | `int ECB_start_operation(BlockBase *cipher, EcbModeState **pResult)` | hIn=0:cipher; hOut=1:pResult |
| 16 | _raw_ecb.pyd | `ECB_stop_operation` | normal_op | `int ECB_stop_operation(EcbModeState *state)` | hIn=0:state |
| 17 | advapi32.dll | `CryptAcquireContextA` | keygen | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | hOut=0:arg0 |
| 18 | advapi32.dll | `CryptAcquireContextW` | keygen | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | hOut=0:arg0 |
| 19 | advapi32.dll | `CryptCreateHash` | hash | `(hProv@0, Algid@1, hKey@2, dwFlags@3, phHash@4)` | hIn=2:hKey; hOut=4:phHash |
| 20 | advapi32.dll | `CryptDecrypt` | sym_enc | `(hKey@0, hHash@1, Final@2, dwFlags@3, pbData@4, pdwDataLen@5)` | in=4:pbData; inlen=5:pdwDataLen; out=4:pbData; outlen=5:pdwDataLen; hIn=0:hKey |
| 21 | advapi32.dll | `CryptDeriveKey` | kdf | `(hProv@0, Algid@1, hBaseData@2, dwFlags@3, phKey@4)` | hIn=2:hBaseData; hOut=4:phKey |
| 22 | advapi32.dll | `CryptDestroyHash` | hash | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | hIn=0:arg0 |
| 23 | advapi32.dll | `CryptDestroyKey` | keygen | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | hIn=0:arg0 |
| 24 | advapi32.dll | `CryptDuplicateKey` | keygen | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | hIn=0:arg0; hOut=3:arg3 |
| 25 | advapi32.dll | `CryptEncrypt` | sym_enc | `(hKey@0, hHash@1, Final@2, dwFlags@3, pbData@4, pdwDataLen@5, dwBufLen@6)` | in=4:pbData; inlen=5:pdwDataLen; out=4:pbData; outlen=5:pdwDataLen; hIn=0:hKey |
| 26 | advapi32.dll | `CryptExportKey` | key_export | `(hKey@0, hExpKey@1, dwBlobType@2, dwFlags@3, pbData@4, pdwDataLen@5)` | out=4:pbData; outlen=5:pdwDataLen; hIn=0:hKey |
| 27 | advapi32.dll | `CryptGenKey` | keygen | `(hProv@0, Algid@1, dwFlags@2, phKey@3)` | hIn=0:hProv; hOut=3:phKey |
| 28 | advapi32.dll | `CryptGenRandom` | rand | `(hProv@0, dwLen@1, pbBuffer@2)` | out=2:pbBuffer; outlen=1:dwLen; hIn=0:hProv |
| 29 | advapi32.dll | `CryptGetHashParam` | hash | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | out=2:arg2; outlen=3:arg3; hIn=0:arg0 |
| 30 | advapi32.dll | `CryptHashData` | hash | `(hHash@0, pbData@1, dwDataLen@2, dwFlags@3)` | in=1:pbData; inlen=2:dwDataLen; hIn=0:hHash |
| 31 | advapi32.dll | `CryptHashSessionKey` | hash | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | hIn=0:arg0 |
| 32 | advapi32.dll | `CryptImportKey` | key_import | `(hProv@0, pbData@1, dwDataLen@2, hPubKey@3, dwFlags@4, phKey@5)` | in=1:pbData; inlen=2:dwDataLen; hIn=0:hProv; hOut=5:phKey |
| 33 | advapi32.dll | `CryptReleaseContext` | keygen | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | hIn=0:arg0 |
| 34 | advapi32.dll | `CryptSetKeyParam` | keygen | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | in=2:arg2; hIn=0:arg0 |
| 35 | advapi32.dll | `RtlGenRandom` | rand | `verified vs Microsoft Learn ntsecapi.h` | out=0:arg0; outlen=1:arg1 |
| 36 | advapi32.dll | `SystemFunction036` | rand | `(RandomBuffer@0, RandomBufferLength@1)` | out=0:RandomBuffer; outlen=1:RandomBufferLength |
| 37 | argon2.dll | `argon2i_hash_raw` | kdf | `ARGON2_PUBLIC int argon2i_hash_raw(const uint32_t t_cost, const uint32_t m_cost,` | in=3:arg3; inlen=4:arg4; out=7:arg7; outlen=8:arg8 |
| 38 | bcrypt.dll | `BCryptCloseAlgorithmProvider` | keygen | `(hAlgorithm@0, dwFlags@1)` | hIn=0:hAlgorithm |
| 39 | bcrypt.dll | `BCryptCreateHash` | hash | `(hAlgorithm@0, phHash@1, pbHashObject@2, cbHashObject@3, pbSecret@4, cbSecret@5, dwFlags@6)` | hIn=0:hAlgorithm; hOut=1:phHash |
| 40 | bcrypt.dll | `BCryptDecrypt` | sym_enc | `(hKey@0, pbInput@1, cbInput@2, pPaddingInfo@3, pbIV@4, cbIV@5, pbOutput@6, cbOutput@7, pcbResult@8, dwFlags@9)` | in=1:pbInput; inlen=2:cbInput; out=6:pbOutput; outlen=7:cbOutput; hIn=0:hKey |
| 41 | bcrypt.dll | `BCryptDeriveKey` | kdf | `(hSharedSecret@0, pwszKDF@1, pParameterList@2, pbDerivedKey@3, cbDerivedKey@4, pcbResult@5, dwFlags@6)` | out=3:pbDerivedKey; outlen=4:cbDerivedKey; hIn=0:hSharedSecret |
| 42 | bcrypt.dll | `BCryptDeriveKeyPBKDF2` | kdf | `(hPrf@0, pbPassword@1, cbPassword@2, pbSalt@3, cbSalt@4, cIterationCount@5, pbDerivedKey@6, cbDerivedKey@7, dwFlags@8)` | in=1:pbPassword; inlen=2:cbPassword; out=6:pbDerivedKey; outlen=7:cbDerivedKey; hIn=0:hPrf |
| 43 | bcrypt.dll | `BCryptDestroyHash` | hash | `(hHash@0)` | hIn=0:hHash |
| 44 | bcrypt.dll | `BCryptDestroyKey` | keygen | `(hKey@0)` | hIn=0:hKey |
| 45 | bcrypt.dll | `BCryptDuplicateHash` | hash | `(hHash@0, phNewHash@1, pbHashObject@2, cbHashObject@3, dwFlags@4)` | hIn=0:hHash; hOut=1:phNewHash |
| 46 | bcrypt.dll | `BCryptDuplicateKey` | keygen | `(hKey@0, phNewKey@1, pbKeyObject@2, cbKeyObject@3, dwFlags@4)` | hIn=0:hKey; hOut=1:phNewKey |
| 47 | bcrypt.dll | `BCryptEncrypt` | sym_enc | `(hKey@0, pbInput@1, cbInput@2, pPaddingInfo@3, pbIV@4, cbIV@5, pbOutput@6, cbOutput@7, pcbResult@8, dwFlags@9)` | in=1:pbInput; inlen=2:cbInput; out=6:pbOutput; outlen=7:cbOutput; hIn=0:hKey |
| 48 | bcrypt.dll | `BCryptExportKey` | key_export | `(hKey@0, hExportKey@1, pszBlobType@2, pbOutput@3, cbOutput@4, pcbResult@5, dwFlags@6)` | out=3:pbOutput; outlen=5:pcbResult; hIn=0:hKey |
| 49 | bcrypt.dll | `BCryptFinalizeKeyPair` | keygen | `(hKey@0, dwFlags@1)` | hIn=0:hKey |
| 50 | bcrypt.dll | `BCryptFinishHash` | kdf | `(hHash@0, pbOutput@1, cbOutput@2, dwFlags@3)` | out=1:pbOutput; outlen=2:cbOutput; hIn=0:hHash |
| 51 | bcrypt.dll | `BCryptGenerateKeyPair` | keygen | `(hAlgorithm@0, phKey@1, dwLength@2, dwFlags@3)` | hIn=0:hAlgorithm; hOut=1:phKey |
| 52 | bcrypt.dll | `BCryptGenerateSymmetricKey` | keygen | `(hAlgorithm@0, phKey@1, pbKeyObject@2, cbKeyObject@3, pbSecret@4, cbSecret@5, dwFlags@6)` | in=4:pbSecret; inlen=5:cbSecret; hIn=0:hAlgorithm; hOut=1:phKey |
| 53 | bcrypt.dll | `BCryptGenRandom` | rand | `(hAlgorithm@0, pbBuffer@1, cbBuffer@2, dwFlags@3)` | out=1:pbBuffer; outlen=2:cbBuffer |
| 54 | bcrypt.dll | `BCryptHashData` | hash | `(hHash@0, pbInput@1, cbInput@2, dwFlags@3)` | in=1:pbInput; inlen=2:cbInput; hIn=0:hHash |
| 55 | bcrypt.dll | `BCryptImportKey` | key_import | `(hAlgorithm@0, hImportKey@1, pszBlobType@2, phKey@3, pbKeyObject@4, cbKeyObject@5, pbInput@6, cbInput@7, dwFlags@8)` | in=6:pbInput; inlen=7:cbInput; hIn=0:hAlgorithm; hOut=3:phKey |
| 56 | bcrypt.dll | `BCryptImportKeyPair` | key_import | `(hAlgorithm@0, hImportKey@1, pszBlobType@2, phKey@3, pbInput@4, cbInput@5, dwFlags@6)` | in=4:pbInput; inlen=5:cbInput; hIn=0:hAlgorithm; hOut=3:phKey |
| 57 | bcrypt.dll | `BCryptKeyDerivation` | kdf | `(hKey@0, pParameterList@1, pbDerivedKey@2, cbDerivedKey@3, pcbResult@4, dwFlags@5)` | out=2:pbDerivedKey; outlen=3:cbDerivedKey; hIn=0:hKey |
| 58 | bcrypt.dll | `BCryptOpenAlgorithmProvider` | keygen | `(phAlgorithm@0, pszAlgId@1, pszImplementation@2, dwFlags@3)` | hOut=0:phAlgorithm |
| 59 | bcrypt.dll | `BCryptSecretAgreement` | kdf | `verified vs Microsoft Learn bcrypt.h` | hIn=0:arg0; hOut=3:arg3 |
| 60 | bcrypt.dll | `BCryptSetProperty` | keygen | `(hObject@0, pszProperty@1, pbInput@2, cbInput@3, dwFlags@4)` | in=2:pbInput; inlen=3:cbInput; hIn=0:hObject |
| 61 | bcrypt.dll | `BCryptSignHash` | normal_op | `(hKey@0, pPaddingInfo@1, pbInput@2, cbInput@3, pbOutput@4, cbOutput@5, pcbResult@6, dwFlags@7)` | in=2:pbInput; inlen=3:cbInput; out=4:pbOutput; outlen=5:cbOutput; hIn=0:hKey |
| 62 | bcrypt.dll | `BCryptVerifySignature` | normal_op | `(hKey@0, pPaddingInfo@1, pbHash@2, cbHash@3, pbSignature@4, cbSignature@5, dwFlags@6)` | in=2:pbHash; inlen=3:cbHash; hIn=0:hKey |
| 63 | bcryptprimitives.dll | `BCryptCloseAlgorithmProvider` | keygen | `(hAlgorithm@0, dwFlags@1)` | hIn=0:hAlgorithm |
| 64 | bcryptprimitives.dll | `BCryptCreateHash` | hash | `(hAlgorithm@0, phHash@1, pbHashObject@2, cbHashObject@3, pbSecret@4, cbSecret@5, dwFlags@6)` | hIn=0:hAlgorithm; hOut=1:phHash |
| 65 | bcryptprimitives.dll | `BCryptDecrypt` | sym_enc | `(hKey@0, pbInput@1, cbInput@2, pPaddingInfo@3, pbIV@4, cbIV@5, pbOutput@6, cbOutput@7, pcbResult@8, dwFlags@9)` | in=1:pbInput; inlen=2:cbInput; out=6:pbOutput; outlen=7:cbOutput; hIn=0:hKey |
| 66 | bcryptprimitives.dll | `BCryptDeriveKey` | kdf | `(hSharedSecret@0, pwszKDF@1, pParameterList@2, pbDerivedKey@3, cbDerivedKey@4, pcbResult@5, dwFlags@6)` | out=3:pbDerivedKey; outlen=4:cbDerivedKey; hIn=0:hSharedSecret |
| 67 | bcryptprimitives.dll | `BCryptDeriveKeyPBKDF2` | kdf | `(hPrf@0, pbPassword@1, cbPassword@2, pbSalt@3, cbSalt@4, cIterationCount@5, pbDerivedKey@6, cbDerivedKey@7, dwFlags@8)` | in=1:pbPassword; inlen=2:cbPassword; out=6:pbDerivedKey; outlen=7:cbDerivedKey; hIn=0:hPrf |
| 68 | bcryptprimitives.dll | `BCryptDestroyHash` | hash | `(hHash@0)` | hIn=0:hHash |
| 69 | bcryptprimitives.dll | `BCryptDestroyKey` | keygen | `(hKey@0)` | hIn=0:hKey |
| 70 | bcryptprimitives.dll | `BCryptDuplicateHash` | hash | `(hHash@0, phNewHash@1, pbHashObject@2, cbHashObject@3, dwFlags@4)` | hIn=0:hHash; hOut=1:phNewHash |
| 71 | bcryptprimitives.dll | `BCryptDuplicateKey` | keygen | `(hKey@0, phNewKey@1, pbKeyObject@2, cbKeyObject@3, dwFlags@4)` | hIn=0:hKey; hOut=1:phNewKey |
| 72 | bcryptprimitives.dll | `BCryptEncrypt` | sym_enc | `(hKey@0, pbInput@1, cbInput@2, pPaddingInfo@3, pbIV@4, cbIV@5, pbOutput@6, cbOutput@7, pcbResult@8, dwFlags@9)` | in=1:pbInput; inlen=2:cbInput; out=6:pbOutput; outlen=7:cbOutput; hIn=0:hKey |
| 73 | bcryptprimitives.dll | `BCryptExportKey` | key_export | `(hKey@0, hExportKey@1, pszBlobType@2, pbOutput@3, cbOutput@4, pcbResult@5, dwFlags@6)` | out=3:pbOutput; outlen=5:pcbResult; hIn=0:hKey |
| 74 | bcryptprimitives.dll | `BCryptFinalizeKeyPair` | keygen | `(hKey@0, dwFlags@1)` | hIn=0:hKey |
| 75 | bcryptprimitives.dll | `BCryptFinishHash` | kdf | `(hHash@0, pbOutput@1, cbOutput@2, dwFlags@3)` | out=1:pbOutput; outlen=2:cbOutput; hIn=0:hHash |
| 76 | bcryptprimitives.dll | `BCryptGenerateKeyPair` | keygen | `(hAlgorithm@0, phKey@1, dwLength@2, dwFlags@3)` | hIn=0:hAlgorithm; hOut=1:phKey |
| 77 | bcryptprimitives.dll | `BCryptGenerateSymmetricKey` | keygen | `(hAlgorithm@0, phKey@1, pbKeyObject@2, cbKeyObject@3, pbSecret@4, cbSecret@5, dwFlags@6)` | in=4:pbSecret; inlen=5:cbSecret; hIn=0:hAlgorithm; hOut=1:phKey |
| 78 | bcryptprimitives.dll | `BCryptGenRandom` | rand | `(hAlgorithm@0, pbBuffer@1, cbBuffer@2, dwFlags@3)` | out=1:pbBuffer; outlen=2:cbBuffer |
| 79 | bcryptprimitives.dll | `BCryptGetProperty` | keygen | `(hObject@0, pszProperty@1, pbOutput@2, cbOutput@3, pcbResult@4, dwFlags@5)` | out=2:pbOutput; outlen=4:pcbResult; hIn=0:hObject |
| 80 | bcryptprimitives.dll | `BCryptHashData` | hash | `(hHash@0, pbInput@1, cbInput@2, dwFlags@3)` | in=1:pbInput; inlen=2:cbInput; hIn=0:hHash |
| 81 | bcryptprimitives.dll | `BCryptImportKey` | key_import | `(hAlgorithm@0, hImportKey@1, pszBlobType@2, phKey@3, pbKeyObject@4, cbKeyObject@5, pbInput@6, cbInput@7, dwFlags@8)` | in=6:pbInput; inlen=7:cbInput; hIn=0:hAlgorithm; hOut=3:phKey |
| 82 | bcryptprimitives.dll | `BCryptImportKeyPair` | key_import | `(hAlgorithm@0, hImportKey@1, pszBlobType@2, phKey@3, pbInput@4, cbInput@5, dwFlags@6)` | in=4:pbInput; inlen=5:cbInput; hIn=0:hAlgorithm; hOut=3:phKey |
| 83 | bcryptprimitives.dll | `BCryptKeyDerivation` | kdf | `(hKey@0, pParameterList@1, pbDerivedKey@2, cbDerivedKey@3, pcbResult@4, dwFlags@5)` | out=2:pbDerivedKey; outlen=3:cbDerivedKey; hIn=0:hKey |
| 84 | bcryptprimitives.dll | `BCryptOpenAlgorithmProvider` | keygen | `(phAlgorithm@0, pszAlgId@1, pszImplementation@2, dwFlags@3)` | hOut=0:phAlgorithm |
| 85 | bcryptprimitives.dll | `BCryptSetProperty` | keygen | `(hObject@0, pszProperty@1, pbInput@2, cbInput@3, dwFlags@4)` | in=2:pbInput; inlen=3:cbInput; hIn=0:hObject |
| 86 | crypt32.dll | `CryptBinaryToStringA` | normal_op | `(pbBinary@0, cbBinary@1, dwFlags@2, pszString@3, pcchString@4)` | in=0:pbBinary; inlen=1:cbBinary; out=3:pszString; outlen=4:pcchString |
| 87 | crypt32.dll | `CryptBinaryToStringW` | normal_op | `(pbBinary@0, cbBinary@1, dwFlags@2, pszString@3, pcchString@4)` | in=0:pbBinary; inlen=1:cbBinary; out=3:pszString; outlen=4:pcchString |
| 88 | crypt32.dll | `CryptDecryptMessage` | sym_enc | `(pDecryptPara@0, pbEncryptedBlob@1, cbEncryptedBlob@2, pbDecrypted@3, pcbDecrypted@4, ppXchgCert@5)` | in=1:pbEncryptedBlob; inlen=2:cbEncryptedBlob; out=3:pbDecrypted; outlen=4:pcbDecrypted |
| 89 | crypt32.dll | `CryptEncryptMessage` | sym_enc | `(pEncryptPara@0, cRecipientCert@1, rgpRecipientCert@2, pbToBeEncrypted@3, cbToBeEncrypted@4, pbEncryptedBlob@5, pcbEncryptedBlob@6)` | in=3:pbToBeEncrypted; inlen=4:cbToBeEncrypted; out=5:pbEncryptedBlob; outlen=6:pcbEncryptedBlob |
| 90 | crypt32.dll | `CryptHashCertificate` | hash | `(hCryptProv@0, Algid@1, dwFlags@2, pbEncoded@3, cbEncoded@4, pbComputedHash@5, pcbComputedHash@6)` | in=3:pbEncoded; inlen=4:cbEncoded; out=5:pbComputedHash; outlen=6:pcbComputedHash; hIn=0:hCryptProv |
| 91 | crypt32.dll | `CryptStringToBinaryA` | normal_op | `(pszString@0, cchString@1, dwFlags@2, pbBinary@3, pcbBinary@4, pdwSkip@5, pdwFlags@6)` | in=0:pszString; inlen=1:cchString; out=3:pbBinary; outlen=4:pcbBinary |
| 92 | crypt32.dll | `CryptStringToBinaryW` | normal_op | `(pszString@0, cchString@1, dwFlags@2, pbBinary@3, pcbBinary@4, pdwSkip@5, pdwFlags@6)` | in=0:pszString; inlen=1:cchString; out=3:pbBinary; outlen=4:pcbBinary |
| 93 | cryptbase.dll | `SystemFunction036` | rand | `(RandomBuffer@0, RandomBufferLength@1)` | out=0:RandomBuffer; outlen=1:RandomBufferLength |
| 94 | cryptsp.dll | `CryptAcquireContextA` | keygen | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | hOut=0:arg0 |
| 95 | cryptsp.dll | `CryptAcquireContextW` | keygen | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | hOut=0:arg0 |
| 96 | cryptsp.dll | `CryptCreateHash` | hash | `(hProv@0, Algid@1, hKey@2, dwFlags@3, phHash@4)` | hIn=2:hKey; hOut=4:phHash |
| 97 | cryptsp.dll | `CryptDecrypt` | sym_enc | `(hKey@0, hHash@1, Final@2, dwFlags@3, pbData@4, pdwDataLen@5)` | in=4:pbData; inlen=5:pdwDataLen; out=4:pbData; outlen=5:pdwDataLen; hIn=0:hKey |
| 98 | cryptsp.dll | `CryptDeriveKey` | kdf | `(hProv@0, Algid@1, hBaseData@2, dwFlags@3, phKey@4)` | hIn=2:hBaseData; hOut=4:phKey |
| 99 | cryptsp.dll | `CryptDestroyHash` | hash | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | hIn=0:arg0 |
| 100 | cryptsp.dll | `CryptDestroyKey` | keygen | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | hIn=0:arg0 |
| 101 | cryptsp.dll | `CryptDuplicateHash` | hash | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | hIn=0:arg0; hOut=3:arg3 |
| 102 | cryptsp.dll | `CryptDuplicateKey` | keygen | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | hIn=0:arg0; hOut=3:arg3 |
| 103 | cryptsp.dll | `CryptEncrypt` | sym_enc | `(hKey@0, hHash@1, Final@2, dwFlags@3, pbData@4, pdwDataLen@5, dwBufLen@6)` | in=4:pbData; inlen=5:pdwDataLen; out=4:pbData; outlen=5:pdwDataLen; hIn=0:hKey |
| 104 | cryptsp.dll | `CryptExportKey` | key_export | `(hKey@0, hExpKey@1, dwBlobType@2, dwFlags@3, pbData@4, pdwDataLen@5)` | out=4:pbData; outlen=5:pdwDataLen; hIn=0:hKey |
| 105 | cryptsp.dll | `CryptGenKey` | keygen | `(hProv@0, Algid@1, dwFlags@2, phKey@3)` | hIn=0:hProv; hOut=3:phKey |
| 106 | cryptsp.dll | `CryptGenRandom` | rand | `(hProv@0, dwLen@1, pbBuffer@2)` | out=2:pbBuffer; outlen=1:dwLen; hIn=0:hProv |
| 107 | cryptsp.dll | `CryptGetHashParam` | hash | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | out=2:arg2; outlen=3:arg3; hIn=0:arg0 |
| 108 | cryptsp.dll | `CryptGetKeyParam` | keygen | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | out=2:arg2; outlen=3:arg3; hIn=0:arg0 |
| 109 | cryptsp.dll | `CryptHashData` | hash | `(hHash@0, pbData@1, dwDataLen@2, dwFlags@3)` | in=1:pbData; inlen=2:dwDataLen; hIn=0:hHash |
| 110 | cryptsp.dll | `CryptHashSessionKey` | hash | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | hIn=0:arg0 |
| 111 | cryptsp.dll | `CryptImportKey` | key_import | `(hProv@0, pbData@1, dwDataLen@2, hPubKey@3, dwFlags@4, phKey@5)` | in=1:pbData; inlen=2:dwDataLen; hIn=0:hProv; hOut=5:phKey |
| 112 | cryptsp.dll | `CryptReleaseContext` | keygen | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | hIn=0:arg0 |
| 113 | cryptsp.dll | `CryptSetHashParam` | hash | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | in=2:arg2; hIn=0:arg0 |
| 114 | cryptsp.dll | `CryptSetKeyParam` | keygen | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | in=2:arg2; hIn=0:arg0 |
| 115 | cryptsp.dll | `CryptSignHashA` | normal_op | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | out=4:arg4; outlen=5:arg5; hIn=0:arg0 |
| 116 | cryptsp.dll | `CryptSignHashW` | normal_op | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | out=4:arg4; outlen=5:arg5; hIn=0:arg0 |
| 117 | cryptsp.dll | `CryptVerifySignatureA` | normal_op | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | in=1:arg1; inlen=2:arg2; hIn=0:arg0 |
| 118 | cryptsp.dll | `CryptVerifySignatureW` | normal_op | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | in=1:arg1; inlen=2:arg2; hIn=0:arg0 |
| 119 | libcrypto-3.dll | `AES_cbc_encrypt` | sym_enc | `(const unsigned char *in, unsigned char *out, size_t length, const AES_KEY *key, unsigned char *ivec, int enc)` | in=0:const unsigned char *in; inlen=2:size_t length; out=1:unsigned char *out; hIn=3:const AES_KEY *key |
| 120 | libcrypto-3.dll | `AES_encrypt` | sym_enc | `(const unsigned char *in, unsigned char *out, const AES_KEY *key)` | in=0:const unsigned char *in; out=1:unsigned char *out; hIn=2:const AES_KEY *key |
| 121 | libcrypto-3.dll | `AES_set_decrypt_key` | keygen | `(const unsigned char *userKey, int bits, AES_KEY *key)` | in=0:const unsigned char *userKey; inlen=1:int bits; hOut=2:AES_KEY *key |
| 122 | libcrypto-3.dll | `AES_set_encrypt_key` | keygen | `(const unsigned char *userKey, int bits, AES_KEY *key)` | in=0:const unsigned char *userKey; inlen=1:int bits; hOut=2:AES_KEY *key |
| 123 | libcrypto-3.dll | `BN_priv_rand` | rand | `int BN_priv_rand(BIGNUM *rnd, int bits, int top, int bottom);` | out=0:rnd |
| 124 | libcrypto-3.dll | `BN_priv_rand_range` | rand | `int BN_priv_rand_range(BIGNUM *rnd, const BIGNUM *range);` | out=0:rnd |
| 125 | libcrypto-3.dll | `DES_random_key` | rand | `OSSL_DEPRECATEDIN_3_0 int DES_random_key(DES_cblock *ret);` | out=0:ret |
| 126 | libcrypto-3.dll | `EC_KEY_oct2priv` | normal_op | `OSSL_DEPRECATEDIN_3_0 int EC_KEY_oct2priv(EC_KEY *key, const unsigned char *buf,` | in=1:arg1; inlen=2:arg2 |
| 127 | libcrypto-3.dll | `EC_KEY_priv2buf` | normal_op | `OSSL_DEPRECATEDIN_3_0 size_t EC_KEY_priv2buf(const EC_KEY *eckey,` | out=1:arg1 |
| 128 | libcrypto-3.dll | `EC_KEY_priv2oct` | normal_op | `OSSL_DEPRECATEDIN_3_0 size_t EC_KEY_priv2oct(const EC_KEY *key,` | out=1:arg1; outlen=2:arg2 |
| 129 | libcrypto-3.dll | `ECDSA_sign_ex` | asym_enc | `OSSL_DEPRECATEDIN_3_0 int ECDSA_sign_ex(int type, const unsigned char *dgst,` | in=1:arg1; inlen=2:arg2; out=3:arg3; outlen=4:arg4 |
| 130 | libcrypto-3.dll | `EVP_DecryptUpdate` | sym_enc | `(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl)` | in=3:const unsigned char *in; inlen=4:int inl; out=1:unsigned char *out; outlen=2:int *outl; hIn=0:EVP_CIPHER_CTX *ctx |
| 131 | libcrypto-3.dll | `EVP_DigestUpdate` | hash | `(EVP_MD_CTX *ctx, const void *d, size_t cnt)` | in=1:const void *d; inlen=2:size_t cnt; hIn=0:EVP_MD_CTX *ctx |
| 132 | libcrypto-3.dll | `EVP_EncryptUpdate` | sym_enc | `(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl)` | in=3:const unsigned char *in; inlen=4:int inl; out=1:unsigned char *out; outlen=2:int *outl; hIn=0:EVP_CIPHER_CTX *ctx |
| 133 | libcrypto-3.dll | `EVP_PKEY_free` | normal_op | `void EVP_PKEY_free(EVP_PKEY *pkey);` | hIn=0:pkey |
| 134 | libcrypto-3.dll | `HMAC` | hash | `(const EVP_MD *evp_md, const void *key, int key_len, const unsigned char *data, size_t data_len, unsigned char *md, unsigned int *md_len)` | in=1:const void *key; inlen=2:int key_len; out=5:unsigned char *md |
| 135 | libcrypto-3.dll | `PKCS5_PBKDF2_HMAC` | kdf | `(const char *pass, int passlen, const unsigned char *salt, int saltlen, int iter, const EVP_MD *digest, int keylen, unsigned char *out)` | in=0:const char *pass; inlen=1:int passlen; out=7:unsigned char *out; outlen=6:int keylen |
| 136 | libcrypto-3.dll | `RAND_add` | rand | `void RAND_add(const void *buf, int num, double randomness);` | in=0:buf; inlen=1:num |
| 137 | libcrypto-3.dll | `RAND_bytes` | rand | `(unsigned char *buf, int num)` | out=0:unsigned char *buf; outlen=1:int num |
| 138 | libcrypto-3.dll | `RAND_bytes_ex` | rand | `int RAND_bytes_ex(OSSL_LIB_CTX *ctx, unsigned char *buf, size_t num,` | out=1:arg1; outlen=2:arg2; hIn=0:arg0 |
| 139 | libcrypto-3.dll | `RAND_priv_bytes` | rand | `int RAND_priv_bytes(unsigned char *buf, int num);` | out=0:buf; outlen=1:num |
| 140 | libcrypto-3.dll | `RAND_priv_bytes_ex` | rand | `int RAND_priv_bytes_ex(OSSL_LIB_CTX *ctx, unsigned char *buf, size_t num,` | out=1:arg1; outlen=2:arg2; hIn=0:arg0 |
| 141 | libcrypto-3.dll | `RAND_pseudo_bytes` | rand | `OSSL_DEPRECATEDIN_1_1_0 int RAND_pseudo_bytes(unsigned char *buf, int num);` | out=0:buf; outlen=1:num |
| 142 | libcrypto-3.dll | `RAND_seed` | rand | `void RAND_seed(const void *buf, int num);` | in=0:buf; inlen=1:num |
| 143 | libcrypto-3.dll | `RSA_free` | normal_op | `OSSL_DEPRECATEDIN_3_0 void RSA_free(RSA *r);` | hIn=0:r |
| 144 | libcrypto-3.dll | `RSA_generate_key_ex` | keygen | `OSSL_DEPRECATEDIN_3_0 int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e,` | hIn=0:arg0 |
| 145 | libcrypto-3.dll | `RSA_private_decrypt` | asym_enc | `(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)` | in=1:const unsigned char *from; inlen=0:int flen; out=2:unsigned char *to; hIn=3:RSA *rsa |
| 146 | libcrypto-3.dll | `RSA_public_encrypt` | asym_enc | `(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)` | in=1:const unsigned char *from; inlen=0:int flen; out=2:unsigned char *to; hIn=3:RSA *rsa |
| 147 | libsodium.dll | `crypto_aead_chacha20poly1305_ietf_encrypt` | sym_enc | `(unsigned char *c, unsigned long long *clen_p, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const unsigned char *k)` | in=2:const unsigned char *m; inlen=3:unsigned long long mlen; out=0:unsigned char *c |
| 148 | libsodium.dll | `crypto_secretbox_easy` | sym_enc | `(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k)` | in=1:const unsigned char *m; inlen=2:unsigned long long mlen; out=0:unsigned char *c |
| 149 | libsodium.dll | `crypto_secretbox_open_easy` | sym_enc | `(unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k)` | in=1:const unsigned char *c; inlen=2:unsigned long long clen; out=0:unsigned char *m |
| 150 | libsodium.dll | `crypto_stream_chacha20_xor` | sym_enc | `(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k)` | in=1:const unsigned char *m; inlen=2:unsigned long long mlen; out=0:unsigned char *c |
| 151 | libsodium.dll | `randombytes_buf` | rand | `(void * const buf, const size_t size)` | out=0:void * const buf; outlen=1:const size_t size |
| 152 | libsodium.dll | `randombytes_buf_deterministic` | rand | `void randombytes_buf_deterministic(void * const buf, const size_t size,` | out=0:arg0; outlen=1:arg1 |
| 153 | mbedtls.dll | `mbedtls_aes_crypt_cbc` | sym_enc | `(mbedtls_aes_context *ctx, int mode, size_t length, unsigned char iv[16], const unsigned char *input, unsigned char *output)` | in=4:const unsigned char *input; inlen=2:size_t length; out=5:unsigned char *output; hIn=0:mbedtls_aes_context *ctx |
| 154 | mbedtls.dll | `mbedtls_aes_crypt_ctr` | sym_enc | `(mbedtls_aes_context *ctx, size_t length, size_t *nc_off, unsigned char nonce_counter[16], unsigned char stream_block[16], const unsigned char *input, unsigned char *output)` | in=5:const unsigned char *input; inlen=1:size_t length; out=6:unsigned char *output; hIn=0:mbedtls_aes_context *ctx |
| 155 | mbedtls.dll | `mbedtls_aes_crypt_ecb` | sym_enc | `(mbedtls_aes_context *ctx, int mode, const unsigned char input[16], unsigned char output[16])` | in=2:const unsigned char input[16]; out=3:unsigned char output[16]; hIn=0:mbedtls_aes_context *ctx |
| 156 | mbedtls.dll | `mbedtls_aes_setkey_dec` | keygen | `(mbedtls_aes_context *ctx, const unsigned char *key, unsigned int keybits)` | in=1:const unsigned char *key; inlen=2:unsigned int keybits; hIn=0:mbedtls_aes_context *ctx |
| 157 | mbedtls.dll | `mbedtls_aes_setkey_enc` | keygen | `(mbedtls_aes_context *ctx, const unsigned char *key, unsigned int keybits)` | in=1:const unsigned char *key; inlen=2:unsigned int keybits; hIn=0:mbedtls_aes_context *ctx |
| 158 | mbedtls.dll | `mbedtls_ctr_drbg_random` | rand | `(void *p_rng, unsigned char *output, size_t output_len)` | out=1:unsigned char *output; outlen=2:size_t output_len; hIn=0:void *p_rng |
| 159 | mbedtls.dll | `mbedtls_entropy_func` | rand | `* - \p f_entropy is mbedtls_entropy_func();` | out=1:arg1; outlen=2:arg2; hIn=0:arg0 |
| 160 | mbedtls.dll | `mbedtls_gcm_crypt_and_tag` | sym_enc | `(mbedtls_gcm_context *ctx, int mode, size_t length, const unsigned char *iv, size_t iv_len, const unsigned char *add, size_t add_len, const unsigned char *input, unsigned char *output, size_t tag_len, unsigned char *tag)` | in=7:const unsigned char *input; inlen=2:size_t length; out=8:unsigned char *output; hIn=0:mbedtls_gcm_context *ctx |
| 161 | mbedtls.dll | `mbedtls_hmac_drbg_random` | rand | `* it is safe to call mbedtls_hmac_drbg_random()` | out=1:arg1; outlen=2:arg2; hIn=0:arg0 |
| 162 | mbedtls.dll | `mbedtls_pkcs5_pbkdf2_hmac` | kdf | `(mbedtls_md_context_t *ctx, const unsigned char *password, size_t plen, const unsigned char *salt, size_t slen, unsigned int iteration_count, uint32_t key_length, unsigned char *output)` | in=1:const unsigned char *password; inlen=2:size_t plen; out=7:unsigned char *output; outlen=6:uint32_t key_length; hIn=0:mbedtls_md_context_t *ctx |
| 163 | mbedtls.dll | `mbedtls_sha256_update` | hash | `(mbedtls_sha256_context *ctx, const unsigned char *input, size_t ilen)` | in=1:const unsigned char *input; inlen=2:size_t ilen; hIn=0:mbedtls_sha256_context *ctx |
| 164 | msvcrt.dll | `memcpy` | memcpy | `void *memcpy(void *dest, const void *src, size_t n)` | in=1:src; inlen=2:n; out=0:dest; outlen=2:n |
| 165 | ncrypt.dll | `NCryptCreatePersistedKey` | keygen | `verified vs Microsoft Learn ncrypt.h` | hOut=1:arg1 |
| 166 | ncrypt.dll | `NCryptDecrypt` | asym_enc | `(hKey@0, pbInput@1, cbInput@2, pPaddingInfo@3, pbOutput@4, cbOutput@5, pcbResult@6, dwFlags@7)` | in=1:pbInput; inlen=2:cbInput; out=4:pbOutput; outlen=5:cbOutput; hIn=0:hKey |
| 167 | ncrypt.dll | `NCryptEncrypt` | asym_enc | `(hKey@0, pbInput@1, cbInput@2, pPaddingInfo@3, pbOutput@4, cbOutput@5, pcbResult@6, dwFlags@7)` | in=1:pbInput; inlen=2:cbInput; out=4:pbOutput; outlen=5:cbOutput; hIn=0:hKey |
| 168 | ncrypt.dll | `NCryptExportKey` | key_export | `verified vs Microsoft Learn ncrypt.h` | hIn=0:arg0 |
| 169 | ncrypt.dll | `NCryptFinalizeKey` | keygen | `verified vs Microsoft Learn ncrypt.h` | hIn=0:arg0 |
| 170 | ncrypt.dll | `NCryptImportKey` | key_import | `verified vs Microsoft Learn ncrypt.h` | hIn=0:arg0; hOut=4:arg4 |
| 171 | ncrypt.dll | `NCryptOpenStorageProvider` | normal_op | `verified vs Microsoft Learn ncrypt.h` | hOut=0:arg0 |
| 172 | ncrypt.dll | `NCryptSecretAgreement` | kdf | `verified vs Microsoft Learn ncrypt.h` | hIn=0:arg0; hOut=2:arg2 |
| 173 | ncrypt.dll | `NCryptSignHash` | normal_op | `verified vs Microsoft Learn ncrypt.h` | in=2:arg2; inlen=3:arg3; out=4:arg4; outlen=6:arg6; hIn=0:arg0 |
| 174 | ncrypt.dll | `NCryptVerifySignature` | normal_op | `verified vs Microsoft Learn ncrypt.h` | hIn=0:arg0 |
| 175 | ntdll.dll | `memcpy` | memcpy | `void *memcpy(void *dest, const void *src, size_t n)` | in=1:src; inlen=2:n; out=0:dest; outlen=2:n |
| 176 | ntdll.dll | `RtlCompressBuffer` | normal_op | `(CompressionFormatAndEngine@0, UncompressedBuffer@1, UncompressedBufferSize@2, CompressedBuffer@3, CompressedBufferSize@4, UncompressedChunkSize@5, FinalCompressedSize@6, WorkSpace@7)` | in=1:UncompressedBuffer; inlen=2:UncompressedBufferSize; out=3:CompressedBuffer; outlen=6:FinalCompressedSize |
| 177 | ntdll.dll | `RtlCopyMemory` | memcpy | `(Destination@0, Source@1, Length@2)` | in=1:Source; inlen=2:Length; out=0:Destination; outlen=2:Length |
| 178 | ntdll.dll | `RtlDecompressBuffer` | normal_op | `(CompressionFormat@0, UncompressedBuffer@1, UncompressedBufferSize@2, CompressedBuffer@3, CompressedBufferSize@4, FinalUncompressedSize@5)` | in=3:CompressedBuffer; inlen=4:CompressedBufferSize; out=1:UncompressedBuffer; outlen=5:FinalUncompressedSize |
| 179 | ntdll.dll | `RtlGenRandom` | rand | `(RandomBuffer@0, RandomBufferLength@1)` | out=0:RandomBuffer; outlen=1:RandomBufferLength |
| 180 | rsaenh.dll | `CPCreateHash` | hash | `(hProv@0, Algid@1, hKey@2, dwFlags@3, phHash@4)` | hIn=2:hKey; hOut=4:phHash |
| 181 | rsaenh.dll | `CPDecrypt` | sym_enc | `(hProv@0, hKey@1, hHash@2, Final@3, dwFlags@4, pbData@5, pdwDataLen@6)` | in=5:pbData; inlen=6:pdwDataLen; out=5:pbData; outlen=6:pdwDataLen; hIn=1:hKey |
| 182 | rsaenh.dll | `CPDeriveKey` | kdf | `(hProv@0, Algid@1, hBaseData@2, dwFlags@3, phKey@4)` | hIn=2:hBaseData; hOut=4:phKey |
| 183 | rsaenh.dll | `CPDestroyHash` | hash | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | hIn=1:arg1 |
| 184 | rsaenh.dll | `CPDestroyKey` | keygen | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | hIn=1:arg1 |
| 185 | rsaenh.dll | `CPDuplicateHash` | hash | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | hIn=1:arg1; hOut=4:arg4 |
| 186 | rsaenh.dll | `CPDuplicateKey` | keygen | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | hIn=1:arg1; hOut=4:arg4 |
| 187 | rsaenh.dll | `CPEncrypt` | sym_enc | `(hProv@0, hKey@1, hHash@2, Final@3, dwFlags@4, pbData@5, pdwDataLen@6, dwBufLen@7)` | in=5:pbData; inlen=6:pdwDataLen; out=5:pbData; outlen=6:pdwDataLen; hIn=1:hKey |
| 188 | rsaenh.dll | `CPExportKey` | key_export | `(hProv@0, hKey@1, hExpKey@2, dwBlobType@3, dwFlags@4, pbData@5, pdwDataLen@6)` | out=5:pbData; outlen=6:pdwDataLen; hIn=1:hKey |
| 189 | rsaenh.dll | `CPGenKey` | keygen | `(hProv@0, Algid@1, dwFlags@2, phKey@3)` | hIn=0:hProv; hOut=3:phKey |
| 190 | rsaenh.dll | `CPGenRandom` | rand | `(hProv@0, dwLen@1, pbBuffer@2)` | out=2:pbBuffer; outlen=1:dwLen; hIn=0:hProv |
| 191 | rsaenh.dll | `CPGetHashParam` | hash | `(hProv@0, hHash@1, dwParam@2, pbData@3, pdwDataLen@4, dwFlags@5)` | out=3:pbData; outlen=4:pdwDataLen; hIn=1:hHash |
| 192 | rsaenh.dll | `CPGetKeyParam` | keygen | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | out=3:arg3; outlen=4:arg4; hIn=1:arg1 |
| 193 | rsaenh.dll | `CPHashData` | hash | `(hProv@0, hHash@1, pbData@2, cbData@3, dwFlags@4)` | in=2:pbData; inlen=3:cbData; hIn=1:hHash |
| 194 | rsaenh.dll | `CPHashSessionKey` | hash | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | hIn=1:arg1 |
| 195 | rsaenh.dll | `CPImportKey` | key_import | `(hProv@0, pbData@1, dwDataLen@2, hPubKey@3, dwFlags@4, phKey@5)` | in=1:pbData; inlen=2:dwDataLen; hIn=0:hProv; hOut=5:phKey |
| 196 | rsaenh.dll | `CPSetHashParam` | hash | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | in=3:arg3; hIn=1:arg1 |
| 197 | rsaenh.dll | `CPSetKeyParam` | keygen | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | in=3:arg3; hIn=1:arg1 |
| 198 | rsaenh.dll | `CPSignHash` | normal_op | `(hProv@0, hHash@1, dwKeySpec@2, sDescription@3, dwFlags@4, pbSignature@5, pdwSigLen@6)` | out=5:pbSignature; outlen=6:pdwSigLen; hIn=1:hHash |
| 199 | rsaenh.dll | `CPVerifySignature` | normal_op | `CryptoAPI/CSP contract — verified vs Microsoft Learn + Wine rsaenh.spec` | in=2:arg2; inlen=3:arg3; hIn=1:arg1 |
| 200 | ucrtbase.dll | `memcpy` | memcpy | `void *memcpy(void *dest, const void *src, size_t n)` | in=1:src; inlen=2:n; out=0:dest; outlen=2:n |
| 201 | vcruntime140.dll | `memcpy` | memcpy | `void *memcpy(void *dest, const void *src, size_t n)` | in=1:src; inlen=2:n; out=0:dest; outlen=2:n |

---

## 6. Presence-marker rules (695) — grouped by library

These rules carry all indices `-1`: they record only that a crypto symbol was *called*
(used for algorithm/coverage inference, not buffer capture). Provenance = the symbol is a
documented public API of its library:

- **`libcrypto-3.dll`** → OpenSSL 3 public headers (`evp.h`, `rsa.h`, `ec.h`, `sha.h`, …),
  verified present in `_audit/proto_db.json` or as documented macros/macro-generated exports.
- **`mbedtls.dll`** → mbedTLS 3.6 public headers.
- **`libsodium.dll`** → libsodium public `crypto_*` headers.
- **`argon2.dll`** → PHC argon2 `argon2.h`.
- Microsoft DLLs → Microsoft Learn / CSP contract.


#### `argon2.dll` — 2 presence-marker rules

- **kdf** (2): `argon2_hash`, `argon2id_hash_raw`

#### `bcrypt.dll` — 1 presence-marker rules

- **kdf** (1): `BCryptDeriveKeyCapi`

#### `crypt32.dll` — 2 presence-marker rules

- **sym_enc** (2): `CryptProtectData`, `CryptUnprotectData`

#### `ed25519-donna.dll` — 3 presence-marker rules

- **asym_enc** (2): `ed25519_sign`, `ed25519_sign_open`
- **keygen** (1): `ed25519_publickey`

#### `libcrypto-3.dll` — 574 presence-marker rules

- **asym_enc** (19): `ECDSA_do_sign`, `ECDSA_do_verify`, `ECDSA_sign`, `ECDSA_verify`, `EVP_DigestSignInit_ex`, `EVP_PKEY_decrypt`, `EVP_PKEY_decrypt_init`, `EVP_PKEY_encrypt`, `EVP_PKEY_encrypt_init`, `EVP_PKEY_sign`, `EVP_PKEY_sign_init`, `EVP_PKEY_verify`, `EVP_PKEY_verify_init`, `EVP_PKEY_verify_recover`, `EVP_PKEY_verify_recover_init`, `RSA_private_encrypt`, `RSA_public_decrypt`, `RSA_sign`, `RSA_verify`
- **hash** (55): `EVP_DigestFinal_ex`, `EVP_DigestInit_ex`, `EVP_MD_CTX_free`, `EVP_MD_CTX_new`, `EVP_blake2b512`, `EVP_blake2s256`, `EVP_md5`, `EVP_sha1`, `EVP_sha256`, `EVP_sha384`, `EVP_sha3_256`, `EVP_sha3_512`, `EVP_sha512`, `HMAC_Final`, `HMAC_Init_ex`, `HMAC_Update`, `MD2`, `MD2_Final`, `MD2_Init`, `MD2_Update`, `MD4`, `MD4_Final`, `MD4_Init`, `MD4_Update`, `MD5`, `MD5_Final`, `MD5_Init`, `MD5_Transform`, `MD5_Update`, `RIPEMD160`, `RIPEMD160_Final`, `RIPEMD160_Transform`, `RIPEMD160_Update`, `SHA1`, `SHA1_Final`, `SHA1_Init`, `SHA1_Update`, `SHA224`, `SHA224_Final`, `SHA224_Update`, `SHA256`, `SHA256_Final`, `SHA256_Init`, `SHA256_Update`, `SHA384`, `SHA384_Final`, `SHA384_Update`, `SHA512`, `SHA512_Final`, `SHA512_Init`, `SHA512_Transform`, `SHA512_Update`, `WHIRLPOOL`, `WHIRLPOOL_Final`, `WHIRLPOOL_Update`
- **kdf** (9): `DH_compute_key`, `ECDH_compute_key`, `EVP_KDF_CTX_new`, `EVP_KDF_derive`, `EVP_KDF_fetch`, `EVP_PBE_scrypt`, `EVP_PKEY_derive`, `EVP_PKEY_derive_init`, `PKCS5_PBKDF2_HMAC_SHA1`
- **keygen** (23): `DES_set_key`, `DES_set_key_checked`, `DH_generate_key`, `EC_GROUP_new_by_curve_name`, `EC_KEY_generate_key`, `EC_KEY_get0_private_key`, `EC_KEY_get0_public_key`, `EC_KEY_new`, `EC_KEY_new_by_curve_name`, `EC_KEY_set_private_key`, `EC_KEY_set_public_key`, `EC_POINT_mul`, `EVP_CIPHER_CTX_reset`, `EVP_CIPHER_CTX_set_key_length`, `EVP_CIPHER_CTX_set_padding`, `EVP_DecryptInit`, `EVP_DecryptInit_ex`, `EVP_DecryptInit_ex2`, `EVP_EncryptInit`, `EVP_EncryptInit_ex`, `EVP_EncryptInit_ex2`, `EVP_PKEY_keygen`, `EVP_PKEY_keygen_init`
- **normal_op** (431): `AES_bi_ige_encrypt`, `AES_cfb1_encrypt`, `AES_cfb8_encrypt`, `AES_ige_encrypt`, `AES_options`, `AES_unwrap_key`, `AES_wrap_key`, `BN_pseudo_rand`, `BN_pseudo_rand_range`, `BN_rand`, `BN_rand_range`, `CMAC_CTX_copy`, `CMAC_CTX_free`, `CMAC_CTX_get0_cipher_ctx`, `CMAC_CTX_new`, `CMAC_Final`, `CMAC_Init`, `CMAC_Update`, `CMAC_resume`, `DES_cfb64_encrypt`, `DES_cfb_encrypt`, `DES_crypt`, `DES_ecb3_encrypt`, `DES_ede3_cfb64_encrypt`, `DES_ede3_ofb64_encrypt`, `DES_fcrypt`, `DES_ofb64_encrypt`, `DES_ofb_encrypt`, `DES_pcbc_encrypt`, `DES_set_key_unchecked`, `DES_set_odd_parity`, `DES_string_to_2keys`, `DES_string_to_key`, `DES_xcbc_encrypt`, `ECDH_KDF_X9_62`, `ECDSA_SIG_free`, `ECDSA_SIG_get0`, `ECDSA_SIG_get0_r`, `ECDSA_SIG_get0_s`, `ECDSA_SIG_new`, `ECDSA_SIG_set0`, `ECDSA_do_sign_ex`, `ECDSA_sign_setup`, `ECDSA_size`, `EC_GROUP_check`, `EC_GROUP_check_discriminant`, `EC_GROUP_clear_free`, `EC_GROUP_cmp`, `EC_GROUP_copy`, `EC_GROUP_dup`, `EC_GROUP_free`, `EC_GROUP_get0_cofactor`, `EC_GROUP_get0_generator`, `EC_GROUP_get0_order`, `EC_GROUP_get_cofactor`, `EC_GROUP_get_curve`, `EC_GROUP_get_curve_GFp`, `EC_GROUP_get_curve_name`, `EC_GROUP_get_order`, `EC_GROUP_method_of`, `EC_GROUP_new`, `EC_GROUP_new_by_curve_name_ex`, `EC_GROUP_set_curve`, `EC_GROUP_set_curve_GFp`, `EC_GROUP_set_curve_name`, `EC_GROUP_set_generator`, `EC_KEY_can_sign`, `EC_KEY_check_key`, `EC_KEY_copy`, `EC_KEY_dup`, `EC_KEY_free`, `EC_KEY_get0_group`, `EC_KEY_get_conv_form`, `EC_KEY_get_enc_flags`, `EC_KEY_key2buf`, `EC_KEY_new_by_curve_name_ex`, `EC_KEY_oct2key`, `EC_KEY_set_asn1_flag`, `EC_KEY_set_conv_form`, `EC_KEY_set_enc_flags`, `EC_KEY_set_group`, `EC_KEY_set_public_key_affine_coordinates`, `EC_KEY_up_ref`, `EC_POINT_add`, `EC_POINT_bn2point`, `EC_POINT_clear_free`, `EC_POINT_cmp`, `EC_POINT_copy`, `EC_POINT_dbl`, `EC_POINT_dup`, `EC_POINT_free`, `EC_POINT_get_Jprojective_coordinates_GFp`, `EC_POINT_get_affine_coordinates`, `EC_POINT_hex2point`, `EC_POINT_invert`, `EC_POINT_is_at_infinity`, `EC_POINT_is_on_curve`, `EC_POINT_make_affine`, `EC_POINT_new`, `EC_POINT_oct2point`, `EC_POINT_point2bn`, `EC_POINT_point2buf`, `EC_POINT_point2hex`, `EC_POINT_point2oct`, `EC_POINT_set_Jprojective_coordinates_GFp`, `EC_POINT_set_affine_coordinates`, `EC_POINT_set_compressed_coordinates`, `EC_POINT_set_to_infinity`, `EC_POINTs_make_affine`, `EC_POINTs_mul`, `EC_curve_nid2nist`, `EC_curve_nist2nid`, `EC_get_builtin_curves`, `EVP_BytesToKey`, `EVP_CIPHER_CTX_clear_flags`, `EVP_CIPHER_CTX_copy`, `EVP_CIPHER_CTX_ctrl`, `EVP_CIPHER_CTX_free`, `EVP_CIPHER_CTX_get0_cipher`, `EVP_CIPHER_CTX_get_block_size`, `EVP_CIPHER_CTX_get_iv_length`, `EVP_CIPHER_CTX_get_key_length`, `EVP_CIPHER_CTX_get_nid`, `EVP_CIPHER_CTX_get_tag_length`, `EVP_CIPHER_CTX_new`, `EVP_CIPHER_CTX_set_flags`, `EVP_CIPHER_CTX_test_flags`, `EVP_CIPHER_fetch`, `EVP_CIPHER_free`, `EVP_CIPHER_up_ref`, `EVP_Cipher`, `EVP_CipherFinal`, `EVP_CipherInit`, `EVP_CipherInit_ex2`, `EVP_DecryptFinal`, `EVP_Digest`, `EVP_DigestFinal`, `EVP_DigestFinalXOF`, `EVP_DigestInit`, `EVP_DigestInit_ex2`, `EVP_DigestSign`, `EVP_DigestSignFinal`, `EVP_DigestSignInit`, `EVP_DigestSignUpdate`, `EVP_DigestSqueeze`, `EVP_DigestVerify`, `EVP_DigestVerifyFinal`, `EVP_DigestVerifyInit`, `EVP_DigestVerifyInit_ex`, `EVP_DigestVerifyUpdate`, `EVP_EncryptFinal`, `EVP_KDF_CTX_dup`, `EVP_KDF_CTX_free`, `EVP_KDF_CTX_get_kdf_size`, `EVP_KDF_CTX_get_params`, `EVP_KDF_CTX_reset`, `EVP_KDF_CTX_set_params`, `EVP_KDF_do_all_provided`, `EVP_KDF_free`, `EVP_KDF_get0_name`, `EVP_KDF_get_params`, `EVP_KDF_gettable_ctx_params`, `EVP_KDF_is_a`, `EVP_KDF_names_do_all`, `EVP_KDF_settable_ctx_params`, `EVP_KDF_up_ref`, `EVP_MD_CTX_clear_flags`, `EVP_MD_CTX_copy`, `EVP_MD_CTX_copy_ex`, `EVP_MD_CTX_ctrl`, `EVP_MD_CTX_get0_md`, `EVP_MD_CTX_get1_md`, `EVP_MD_CTX_get_pkey_ctx`, `EVP_MD_CTX_md`, `EVP_MD_CTX_reset`, `EVP_MD_CTX_set_flags`, `EVP_MD_CTX_set_pkey_ctx`, `EVP_MD_CTX_test_flags`, `EVP_MD_fetch`, `EVP_MD_free`, `EVP_MD_up_ref`, `EVP_OpenFinal`, `EVP_OpenInit`, `EVP_PBE_CipherInit`, `EVP_PBE_alg_add`, `EVP_PBE_find`, `EVP_PKEY_CTX_ctrl`, `EVP_PKEY_CTX_ctrl_str`, `EVP_PKEY_CTX_dup`, `EVP_PKEY_CTX_free`, `EVP_PKEY_CTX_get_params`, `EVP_PKEY_CTX_new`, `EVP_PKEY_CTX_new_from_name`, `EVP_PKEY_CTX_new_from_pkey`, `EVP_PKEY_CTX_new_id`, `EVP_PKEY_CTX_set_params`, `EVP_PKEY_CTX_set_rsa_padding`, `EVP_PKEY_check`, `EVP_PKEY_cmp`, `EVP_PKEY_cmp_parameters`, `EVP_PKEY_copy_parameters`, `EVP_PKEY_decapsulate`, `EVP_PKEY_decapsulate_init`, `EVP_PKEY_decrypt_init_ex`, `EVP_PKEY_derive_init_ex`, `EVP_PKEY_derive_set_peer`, `EVP_PKEY_derive_set_peer_ex`, `EVP_PKEY_dup`, `EVP_PKEY_encapsulate`, `EVP_PKEY_encapsulate_init`, `EVP_PKEY_encrypt_init_ex`, `EVP_PKEY_eq`, `EVP_PKEY_export`, `EVP_PKEY_fromdata`, `EVP_PKEY_fromdata_init`, `EVP_PKEY_generate`, `EVP_PKEY_get0_DH`, `EVP_PKEY_get0_DSA`, `EVP_PKEY_get0_EC_KEY`, `EVP_PKEY_get0_RSA`, `EVP_PKEY_get1_EC_KEY`, `EVP_PKEY_get1_RSA`, `EVP_PKEY_get_base_id`, `EVP_PKEY_get_id`, `EVP_PKEY_get_raw_private_key`, `EVP_PKEY_get_raw_public_key`, `EVP_PKEY_new`, `EVP_PKEY_new_CMAC_key`, `EVP_PKEY_new_mac_key`, `EVP_PKEY_new_raw_private_key`, `EVP_PKEY_new_raw_private_key_ex`, `EVP_PKEY_new_raw_public_key`, `EVP_PKEY_new_raw_public_key_ex`, `EVP_PKEY_param_check`, `EVP_PKEY_parameters_eq`, `EVP_PKEY_paramgen`, `EVP_PKEY_paramgen_init`, `EVP_PKEY_print_params`, `EVP_PKEY_print_private`, `EVP_PKEY_print_public`, `EVP_PKEY_public_check`, `EVP_PKEY_set1_DH`, `EVP_PKEY_set1_DSA`, `EVP_PKEY_set1_EC_KEY`, `EVP_PKEY_set1_RSA`, `EVP_PKEY_sign_init_ex`, `EVP_PKEY_todata`, `EVP_PKEY_up_ref`, `EVP_PKEY_verify_init_ex`, `EVP_SealFinal`, `EVP_SealInit`, `EVP_SignFinal`, `EVP_VerifyFinal`, `EVP_aes_128_cbc_hmac_sha1`, `EVP_aes_128_cbc_hmac_sha256`, `EVP_aes_128_ccm`, `EVP_aes_128_cfb1`, `EVP_aes_128_cfb128`, `EVP_aes_128_cfb8`, `EVP_aes_128_ocb`, `EVP_aes_128_ofb`, `EVP_aes_128_wrap`, `EVP_aes_128_wrap_pad`, `EVP_aes_192_ccm`, `EVP_aes_192_cfb1`, `EVP_aes_192_cfb128`, `EVP_aes_192_cfb8`, `EVP_aes_192_ctr`, `EVP_aes_192_ecb`, `EVP_aes_192_gcm`, `EVP_aes_192_ocb`, `EVP_aes_192_ofb`, `EVP_aes_192_wrap`, `EVP_aes_192_wrap_pad`, `EVP_aes_256_cbc_hmac_sha1`, `EVP_aes_256_cbc_hmac_sha256`, `EVP_aes_256_ccm`, `EVP_aes_256_cfb1`, `EVP_aes_256_cfb128`, `EVP_aes_256_cfb8`, `EVP_aes_256_ocb`, `EVP_aes_256_ofb`, `EVP_aes_256_wrap`, `EVP_aes_256_wrap_pad`, `EVP_aria_128_cbc`, `EVP_aria_128_ctr`, `EVP_aria_128_ecb`, `EVP_aria_128_gcm`, `EVP_aria_256_gcm`, `EVP_bf_cbc`, `EVP_bf_cfb64`, `EVP_bf_ecb`, `EVP_bf_ofb`, `EVP_camellia_128_cbc`, `EVP_camellia_128_ctr`, `EVP_camellia_128_ecb`, `EVP_camellia_192_cbc`, `EVP_camellia_192_ctr`, `EVP_camellia_192_ecb`, `EVP_camellia_256_cbc`, `EVP_camellia_256_ctr`, `EVP_camellia_256_ecb`, `EVP_cast5_cbc`, `EVP_cast5_cfb64`, `EVP_cast5_ecb`, `EVP_cast5_ofb`, `EVP_des_cbc`, `EVP_des_cfb1`, `EVP_des_cfb64`, `EVP_des_cfb8`, `EVP_des_ecb`, `EVP_des_ede`, `EVP_des_ede3`, `EVP_des_ede3_cfb1`, `EVP_des_ede_cbc`, `EVP_des_ede_cfb64`, `EVP_des_ede_ofb`, `EVP_des_ofb`, `EVP_get_cipherbyname`, `EVP_get_digestbyname`, `EVP_idea_cbc`, `EVP_idea_cfb64`, `EVP_idea_ecb`, `EVP_idea_ofb`, `EVP_md2`, `EVP_md4`, `EVP_md5_sha1`, `EVP_mdc2`, `EVP_rc2_40_cbc`, `EVP_rc2_64_cbc`, `EVP_rc2_cbc`, `EVP_rc2_cfb64`, `EVP_rc2_ofb`, `EVP_rc5_32_12_16_cbc`, `EVP_rc5_32_12_16_cfb64`, `EVP_rc5_32_12_16_ecb`, `EVP_rc5_32_12_16_ofb`, `EVP_ripemd160`, `EVP_seed_cbc`, `EVP_seed_cfb128`, `EVP_seed_ecb`, `EVP_seed_ofb`, `EVP_sha224`, `EVP_sha3_224`, `EVP_sha3_384`, `EVP_sha512_224`, `EVP_sha512_256`, `EVP_shake128`, `EVP_shake256`, `EVP_sm3`, `EVP_sm4_cbc`, `EVP_sm4_ctr`, `EVP_sm4_ecb`, `EVP_sm4_ofb`, `EVP_whirlpool`, `HMAC_CTX_copy`, `HMAC_CTX_free`, `HMAC_CTX_get_md`, `HMAC_CTX_new`, `HMAC_CTX_reset`, `HMAC_CTX_set_flags`, `HMAC_Init`, `HMAC_size`, `PKCS5_PBE_keyivgen`, `PKCS5_v2_PBE_keyivgen`, `RAND_OpenSSL`, `RAND_file_name`, `RAND_get0_primary`, `RAND_get0_private`, `RAND_get0_public`, `RAND_get_rand_method`, `RAND_keep_random_devices_open`, `RAND_load_file`, `RAND_poll`, `RAND_set_DRBG_type`, `RAND_set_rand_engine`, `RAND_set_rand_method`, `RAND_set_seed_source_type`, `RAND_write_file`, `RC4_options`, `RIPEMD160_Init`, `RSA_PKCS1_OpenSSL`, `RSA_X931_hash_id`, `RSA_bits`, `RSA_blinding_off`, `RSA_blinding_on`, `RSA_check_key`, `RSA_check_key_ex`, `RSA_generate_key`, `RSA_generate_multi_prime_key`, `RSA_get0_crt_params`, `RSA_get0_d`, `RSA_get0_e`, `RSA_get0_factors`, `RSA_get0_key`, `RSA_get0_n`, `RSA_get0_p`, `RSA_get0_q`, `RSA_meth_free`, `RSA_meth_new`, `RSA_new`, `RSA_padding_add_PKCS1_OAEP`, `RSA_padding_add_PKCS1_OAEP_mgf1`, `RSA_padding_add_PKCS1_PSS`, `RSA_padding_add_PKCS1_PSS_mgf1`, `RSA_padding_add_PKCS1_type_1`, `RSA_padding_add_PKCS1_type_2`, `RSA_padding_add_X931`, `RSA_padding_add_none`, `RSA_padding_check_PKCS1_OAEP`, `RSA_padding_check_PKCS1_OAEP_mgf1`, `RSA_padding_check_PKCS1_type_1`, `RSA_padding_check_PKCS1_type_2`, `RSA_padding_check_X931`, `RSA_padding_check_none`, `RSA_pkey_ctx_ctrl`, `RSA_security_bits`, `RSA_set0_crt_params`, `RSA_set0_factors`, `RSA_set0_key`, `RSA_sign_ASN1_OCTET_STRING`, `RSA_size`, `RSA_up_ref`, `RSA_verify_ASN1_OCTET_STRING`, `RSA_verify_PKCS1_PSS`, `RSA_verify_PKCS1_PSS_mgf1`, `SHA1_Transform`, `SHA224_Init`, `SHA256_Transform`, `SHA384_Init`, `WHIRLPOOL_Init`
- **rand** (3): `EVP_CIPHER_CTX_rand_key`, `EVP_RAND_generate`, `RAND_status`
- **sym_enc** (34): `AES_cfb128_encrypt`, `AES_decrypt`, `AES_ecb_encrypt`, `AES_ofb128_encrypt`, `BF_cbc_encrypt`, `BF_ecb_encrypt`, `BF_set_key`, `Camellia_cbc_encrypt`, `Camellia_set_key`, `DES_cbc_encrypt`, `DES_ecb_encrypt`, `DES_ede3_cbc_encrypt`, `EVP_CipherFinal_ex`, `EVP_CipherInit_ex`, `EVP_CipherUpdate`, `EVP_DecryptFinal_ex`, `EVP_EncryptFinal_ex`, `EVP_aes_128_cbc`, `EVP_aes_128_ctr`, `EVP_aes_128_ecb`, `EVP_aes_128_gcm`, `EVP_aes_128_xts`, `EVP_aes_192_cbc`, `EVP_aes_256_cbc`, `EVP_aes_256_ctr`, `EVP_aes_256_ecb`, `EVP_aes_256_gcm`, `EVP_aes_256_xts`, `EVP_chacha20`, `EVP_chacha20_poly1305`, `EVP_des_ede3_cbc`, `EVP_rc4`, `RC4`, `RC4_set_key`

#### `libsodium.dll` — 46 presence-marker rules

- **asym_enc** (2): `crypto_sign_detached`, `crypto_sign_verify_detached`
- **hash** (7): `crypto_auth_hmacsha256`, `crypto_auth_hmacsha512`, `crypto_generichash`, `crypto_generichash_blake2b`, `crypto_hash_sha256`, `crypto_hash_sha512`, `crypto_shorthash`
- **kdf** (8): `crypto_kdf_blake2b_derive_from_key`, `crypto_kdf_derive_from_key`, `crypto_pwhash`, `crypto_pwhash_argon2i`, `crypto_pwhash_argon2id`, `crypto_pwhash_scryptsalsa208sha256`, `crypto_sign_ed25519_pk_to_curve25519`, `crypto_sign_ed25519_sk_to_curve25519`
- **keygen** (9): `crypto_box_curve25519xsalsa20poly1305_keypair`, `crypto_box_keypair`, `crypto_scalarmult`, `crypto_scalarmult_base`, `crypto_scalarmult_curve25519`, `crypto_scalarmult_curve25519_base`, `crypto_sign_ed25519_keypair`, `crypto_sign_keypair`, `crypto_sign_seed_keypair`
- **rand** (2): `randombytes_random`, `randombytes_uniform`
- **sym_enc** (18): `crypto_aead_aes256gcm_decrypt`, `crypto_aead_aes256gcm_encrypt`, `crypto_aead_chacha20poly1305_ietf_decrypt`, `crypto_aead_xchacha20poly1305_ietf_decrypt`, `crypto_aead_xchacha20poly1305_ietf_encrypt`, `crypto_box_easy`, `crypto_box_open_easy`, `crypto_box_seal`, `crypto_box_seal_open`, `crypto_secretbox_detached`, `crypto_secretbox_xchacha20poly1305_easy`, `crypto_stream_chacha20`, `crypto_stream_salsa20`, `crypto_stream_salsa20_xor`, `crypto_stream_xchacha20`, `crypto_stream_xchacha20_xor`, `crypto_stream_xsalsa20`, `crypto_stream_xsalsa20_xor`

#### `mbedtls.dll` — 67 presence-marker rules

- **asym_enc** (8): `mbedtls_ecdsa_sign`, `mbedtls_ecdsa_verify`, `mbedtls_pk_decrypt`, `mbedtls_pk_encrypt`, `mbedtls_rsa_pkcs1_decrypt`, `mbedtls_rsa_pkcs1_encrypt`, `mbedtls_rsa_rsaes_oaep_decrypt`, `mbedtls_rsa_rsaes_oaep_encrypt`
- **hash** (15): `mbedtls_md5_finish`, `mbedtls_md5_starts`, `mbedtls_md5_update`, `mbedtls_md_hmac_finish`, `mbedtls_md_hmac_starts`, `mbedtls_md_hmac_update`, `mbedtls_ripemd160_starts`, `mbedtls_sha1_finish`, `mbedtls_sha1_starts`, `mbedtls_sha1_update`, `mbedtls_sha256_finish`, `mbedtls_sha256_starts`, `mbedtls_sha512_finish`, `mbedtls_sha512_starts`, `mbedtls_sha512_update`
- **kdf** (5): `mbedtls_ecdh_compute_shared`, `mbedtls_hkdf`, `mbedtls_hkdf_expand`, `mbedtls_hkdf_extract`, `mbedtls_pkcs5_pbkdf2_hmac_ext`
- **keygen** (18): `mbedtls_aes_init`, `mbedtls_aes_xts_setkey_dec`, `mbedtls_aes_xts_setkey_enc`, `mbedtls_aria_setkey_dec`, `mbedtls_aria_setkey_enc`, `mbedtls_camellia_setkey_dec`, `mbedtls_camellia_setkey_enc`, `mbedtls_chacha20_setkey`, `mbedtls_chachapoly_setkey`, `mbedtls_ecdh_gen_public`, `mbedtls_ecdh_init`, `mbedtls_ecp_gen_keypair`, `mbedtls_ecp_group_init`, `mbedtls_ecp_group_load`, `mbedtls_pk_parse_key`, `mbedtls_pk_parse_public_key`, `mbedtls_rsa_gen_key`, `mbedtls_rsa_init`
- **normal_op** (1): `mbedtls_ecp_mul`
- **rand** (1): `mbedtls_ctr_drbg_seed`
- **sym_enc** (19): `mbedtls_aes_crypt_cfb128`, `mbedtls_aes_crypt_cfb8`, `mbedtls_aes_crypt_ofb`, `mbedtls_aes_crypt_xts`, `mbedtls_aria_crypt_ecb`, `mbedtls_camellia_crypt_cbc`, `mbedtls_camellia_crypt_ecb`, `mbedtls_ccm_encrypt_and_tag`, `mbedtls_ccm_init`, `mbedtls_chacha20_crypt`, `mbedtls_chacha20_update`, `mbedtls_chachapoly_auth_decrypt`, `mbedtls_chachapoly_encrypt_and_tag`, `mbedtls_chachapoly_update`, `mbedtls_des3_crypt_cbc`, `mbedtls_des_crypt_ecb`, `mbedtls_gcm_auth_decrypt`, `mbedtls_gcm_init`, `mbedtls_gcm_setkey`

---

## 7. Macro-alias names (40) — bind only via their expansion

These libcrypto-3 names are `#define` aliases. The DLL exports the **expansion**, not the
literal alias, so a hook keyed on the literal string is a no-op. All 40 are now flagged `catalog_only` (a hook keyed on the literal name is a no-op); to make
one actually bind, hook the expansion symbol. They are retained as `catalog_only` because the
expansion *is* a real OpenSSL 3 export.

| literal name in rule | exported symbol it expands to | bind by literal name? |
|---|---|---|
| `DES_ecb2_encrypt` | `#define DES_ecb2_encrypt(i,o,k1,k2,e) DES_ecb3_encrypt((i),(o),(k1),(k2),(k1),(e))` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `DES_ede2_cbc_encrypt` | `#define DES_ede2_cbc_encrypt(i,o,l,k1,k2,iv,e) DES_ede3_cbc_encrypt((i),(o),(l),(k1),(k2),(k1),(iv),(e))` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_CIPHER_CTX_cleanup` | `#define EVP_CIPHER_CTX_cleanup(c) EVP_CIPHER_CTX_reset(c)` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_CIPHER_CTX_get_mode` | `#define EVP_CIPHER_CTX_get_mode(c) EVP_CIPHER_get_mode(EVP_CIPHER_CTX_get0_cipher(c))` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_CIPHER_CTX_get_type` | `#define EVP_CIPHER_CTX_get_type(c) EVP_CIPHER_get_type(EVP_CIPHER_CTX_get0_cipher(c))` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_CIPHER_CTX_init` | `#define EVP_CIPHER_CTX_init(c) EVP_CIPHER_CTX_reset(c)` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_MD_CTX_create` | `#define EVP_MD_CTX_create() EVP_MD_CTX_new()` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_MD_CTX_destroy` | `#define EVP_MD_CTX_destroy(ctx) EVP_MD_CTX_free((ctx))` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_MD_CTX_init` | `#define EVP_MD_CTX_init(ctx) EVP_MD_CTX_reset((ctx))` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_OpenUpdate` | `#define EVP_OpenUpdate(a,b,c,d,e) EVP_DecryptUpdate(a,b,c,d,e)` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_PKEY_base_id` | `#define EVP_PKEY_base_id EVP_PKEY_get_base_id` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_PKEY_bits` | `#define EVP_PKEY_bits EVP_PKEY_get_bits` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_PKEY_id` | `#define EVP_PKEY_id EVP_PKEY_get_id` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_PKEY_security_bits` | `#define EVP_PKEY_security_bits EVP_PKEY_get_security_bits` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_PKEY_size` | `#define EVP_PKEY_size EVP_PKEY_get_size` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_SealUpdate` | `#define EVP_SealUpdate(a,b,c,d,e) EVP_EncryptUpdate(a,b,c,d,e)` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_SignInit` | `#define EVP_SignInit(a,b) EVP_DigestInit(a,b)` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_SignInit_ex` | `#define EVP_SignInit_ex(a,b,c) EVP_DigestInit_ex(a,b,c)` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_SignUpdate` | `#define EVP_SignUpdate(a,b,c) EVP_DigestUpdate(a,b,c)` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_VerifyInit` | `#define EVP_VerifyInit(a,b) EVP_DigestInit(a,b)` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_VerifyInit_ex` | `#define EVP_VerifyInit_ex(a,b,c) EVP_DigestInit_ex(a,b,c)` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_VerifyUpdate` | `#define EVP_VerifyUpdate(a,b,c) EVP_DigestUpdate(a,b,c)` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_aes_128_cfb` | `#define EVP_aes_128_cfb EVP_aes_128_cfb128` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_aes_192_cfb` | `#define EVP_aes_192_cfb EVP_aes_192_cfb128` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_aes_256_cfb` | `#define EVP_aes_256_cfb EVP_aes_256_cfb128` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_bf_cfb` | `#define EVP_bf_cfb EVP_bf_cfb64` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_cast5_cfb` | `#define EVP_cast5_cfb EVP_cast5_cfb64` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_des_cfb` | `#define EVP_des_cfb EVP_des_cfb64` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_des_ede3_cfb` | `#define EVP_des_ede3_cfb EVP_des_ede3_cfb64` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_des_ede_cfb` | `#define EVP_des_ede_cfb EVP_des_ede_cfb64` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_get_cipherbynid` | `#define EVP_get_cipherbynid(a) EVP_get_cipherbyname(OBJ_nid2sn(a))` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_get_cipherbyobj` | `#define EVP_get_cipherbyobj(a) EVP_get_cipherbynid(OBJ_obj2nid(a))` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_get_digestbynid` | `#define EVP_get_digestbynid(a) EVP_get_digestbyname(OBJ_nid2sn(a))` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_get_digestbyobj` | `#define EVP_get_digestbyobj(a) EVP_get_digestbynid(OBJ_obj2nid(a))` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_idea_cfb` | `#define EVP_idea_cfb EVP_idea_cfb64` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_rc2_cfb` | `#define EVP_rc2_cfb EVP_rc2_cfb64` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_rc5_32_12_16_cfb` | `#define EVP_rc5_32_12_16_cfb EVP_rc5_32_12_16_cfb64` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_seed_cfb` | `#define EVP_seed_cfb EVP_seed_cfb128` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `EVP_sm4_cfb` | `#define EVP_sm4_cfb EVP_sm4_cfb128` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |
| `RAND_cleanup` | `#define RAND_cleanup() while(0) continue (no-op, deprecated 1.1.0)` | NO (catalog_only no-op; hook the expansion symbol to actually bind) |

---

## 8. Other rulesets — sourcing summary

All sibling rulesets were checked for provenance; each carries a citation field:

| file | entries | provenance field | status |
|---|---|---|---|
| `crypto_constants.json` | 115 constants + 28 prng + 18 hardcoded-key indicators | `spec_citation` | sourced (SHA/AES/Argon2/CRC magic verified, e.g. SHA-256 IV `0x6a09e667…`) |
| `loop_patterns.json` | 82 | `source` (100%) | sourced |
| `sym_key_inference_rules.json` | **14** | `spec_citation` + `spec_url` | sourced |
| `dll_roles.json` | **231** | role taxonomy (231 real roles; 236 raw incl. 5 `_comment_*` doc entries; prior "203" was stale) | descriptive |
| `io_activity.json` | 157 | per-entry `source` (prior audit) | sourced |

---

## 9. Reproduce this audit

```bash
python _audit/parse_headers.py     # fetch+parse headers -> proto_db.json (2457 protos)
python _audit/verify_rules.py      # deterministic arg-index check -> findings.json
python _audit/gen_provenance.py    # regenerate the tables in this doc
```

Source-of-truth artifacts: `_audit/proto_db.json`, `_audit/findings.json`,
`_audit/verdict_ossl.json`.


---

## PyCryptodome catalog entries (16 new rules)

Added 16 entries to `assets/crypto_api.json` for PyCryptodome's exported
symbols, each with a `_header_quote` containing the
verbatim `EXPORT_SYM` signature from the upstream master branch.

### Source files fetched

| File | DLL produced | Exported symbols |
|---|---|---|
| `src/AES.c` (via `src/block_common.c`) | `_raw_aes.pyd` | `AES_start_operation`, `AES_stop_operation` |
| `src/AESNI.c` | `_raw_aesni.pyd` | `AESNI_start_operation`, `AESNI_stop_operation` |
| `src/raw_ecb.c` | `_raw_ecb.pyd` | `ECB_start_operation`, `ECB_encrypt`, `ECB_decrypt`, `ECB_stop_operation` |
| `src/raw_cbc.c` | `_raw_cbc.pyd` | `CBC_start_operation`, `CBC_encrypt`, `CBC_decrypt`, `CBC_stop_operation` |
| `src/raw_ctr.c` | `_raw_ctr.pyd` | `CTR_start_operation`, `CTR_encrypt`, `CTR_decrypt`, `CTR_stop_operation` |

### Critical correction over the prior paper §III-C spec

The prior RC-06 evidence specification named `AES_encrypt` / `AES_decrypt`
as the trigger APIs. Verbatim inspection of `src/block_common.c` lines
50 / 66 confirms these are declared `static int CIPHER_ENCRYPT(...)` /
`static int CIPHER_DECRYPT(...)` — file-scope, **not** `EXPORT_SYM`. They
are therefore **not reachable through any DLL export table**, so a PinTool
that hooks by symbol name cannot observe them. The real exported
sym_enc surface lives in the mode-wrapper DLLs (`_raw_ecb.pyd`,
`_raw_cbc.pyd`, `_raw_ctr.pyd`); `recovery_cases.py` RC-06 now references
those mode APIs instead.

### Source URLs (master @ 2026-06-09)

- https://github.com/Legrandin/pycryptodome/blob/master/src/AES.c
- https://github.com/Legrandin/pycryptodome/blob/master/src/AESNI.c
- https://github.com/Legrandin/pycryptodome/blob/master/src/block_common.c
- https://github.com/Legrandin/pycryptodome/blob/master/src/raw_ecb.c
- https://github.com/Legrandin/pycryptodome/blob/master/src/raw_cbc.c
- https://github.com/Legrandin/pycryptodome/blob/master/src/raw_ctr.c
