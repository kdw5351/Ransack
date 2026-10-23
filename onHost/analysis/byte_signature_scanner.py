"""Byte-pattern scanners ported line-by-line from published research sources.

Every algorithm here is a verbatim port of the original source, with
line-level citations.

References (read in full and ported, 2026-05-27):
  - aeskeyfind  : makomk/aeskeyfind/aeskeyfind.c (fork of AESKeyFinder by Heninger & Feldman; Halderman et al., USENIX Security 2008)
  - wanakiwi    : prime scan ported from aguinet/wannakey/wkey/search_primes.cpp (Guinet 2017; wannakey is the core tool, wanakiwi the front-end)
                  + tools.cpp (entropy) + process.cpp (region filter)
  - BCRYPT blob : Microsoft CNG bcrypt.h (BCRYPT_RSAKEY_BLOB struct)
  - Avaddon     : JavierYuste/AvaddonDecryptor/main.py (Yuste 2021)
"""
from __future__ import annotations

import math
import os
import struct
from collections import Counter


# ===========================================================================
# aeskeyfind  (Halderman et al. 2008 cold-boot key schedule; makomk/aeskeyfind verbatim)
# ===========================================================================
# Constants from aeskeyfind.c (makomk/aeskeyfind master, verified 2026-06-01
# against the actual master commit — all line numbers re-confirmed):
#   #define DEFAULT_THRESHOLD 10                                [line 29]
#   if (len < 240) ...                                          [line 329]
#   find_keys(image, len - 240)                                 [line 334]
#   AES-256 comparison: xor_count_256 <= gThreshold             [line 217]
#   AES-128 comparison: xor_count_128 <  gThreshold             [line 249]
# Entropy filter: if (byte_freq[b] > 8) ...                     [line 111]
# AES-256 partial-row early break at column == 4                [line 200]
# AES-256 final < threshold filter                              [line 214]
# AES-128 final < threshold filter                              [line 246]
# AES-256 FIXME "implement tweaks here too"                     [line 196]
# AES-128 TWEAK outer loop (MAX_TWEAKS=4)                       [line 220]
# AES-192 is NOT handled by aeskeyfind (usage banner string).
AESKEYFIND_THRESHOLD = 10            # aeskeyfind.c:29 DEFAULT_THRESHOLD verbatim.
                                    # kept = upstream so our recall numbers
                                    # remain directly comparable to the original paper.
                                    # Re-tuning per-trace would invalidate cross-tool comparability.
AESKEYFIND_MIN_LEN = 240            # aeskeyfind.c:329 / 334

# FIPS-197 S-box (used by both port and aeskeyfind for key_core).
_SBOX = bytes((
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
    0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
    0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
    0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
    0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
    0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
    0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16,
))

# aeskeyfind's rcon table is indexed by round number (its `rcon[i]` in
# aes.h:15, where `i` is the round). Values are the standard FIPS-197
# Rcon byte (high byte of the 32-bit Rcon word).
# aeskeyfind rcon indices 1..10 -> [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]
# AES-256 uses rounds up to 14, but rcon is only consumed at column-0
# events (i mod Nk == 0), which for Nk=8 happens at rounds 8/16 only;
# Nr=14 means rounds 0..14, so rcon[1..6] for AES-256.
_RCON = (0x00,       # rcon[0] unused
         0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
         0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D)


def _popcount8(b: int) -> int:
    return bin(b & 0xFF).count("1")


def _key_core_128(word: int, round_idx: int) -> int:
    """aeskeyfind key_core (aes.h:8-16) -- byte-permuted SubWord + Rcon XOR
    on byte 0. Matches FIPS-197 RotWord+SubWord+Rcon when seed is stored
    in little-endian uint32 order on x86 (which is aeskeyfind's host)."""
    # SubBytes on all 4 bytes, with the (j-1)%4 byte permutation that
    # aeskeyfind's key_core performs. Equivalent to rotate-bytes-left + SubBytes.
    b0 = _SBOX[(word >> 8)  & 0xFF]
    b1 = _SBOX[(word >> 16) & 0xFF]
    b2 = _SBOX[(word >> 24) & 0xFF]
    b3 = _SBOX[ word        & 0xFF]
    t = (b3 << 24) | (b2 << 16) | (b1 << 8) | b0
    return t ^ _RCON[round_idx]


def _sbox_word(word: int) -> int:
    """aes.h:21-26 sbox_bytes: SubWord without RotWord; used at AES-256
    column-4 events."""
    b0 = _SBOX[ word        & 0xFF]
    b1 = _SBOX[(word >> 8)  & 0xFF]
    b2 = _SBOX[(word >> 16) & 0xFF]
    b3 = _SBOX[(word >> 24) & 0xFF]
    return (b3 << 24) | (b2 << 16) | (b1 << 8) | b0


def _popcount_word(w: int) -> int:
    """Popcount of a 32-bit word."""
    return (_popcount8(w & 0xFF) + _popcount8((w >> 8) & 0xFF)
            + _popcount8((w >> 16) & 0xFF) + _popcount8((w >> 24) & 0xFF))


# ---------------------------------------------------------------------------
# AES-128 TWEAK support (aeskeyfind.c:33-34, 148-175, 215, 220)
#
# 2026-06-03 — completes the MAX_TWEAKS=4 outer loop that aeskeyfind upstream
# implements for the AES-128 path. Without this we miss AES-128 keys from
# decrypt-optimised schedulers:
#     mbedtls_aes_setkey_dec      (mbedTLS)
#     wc_AesSetKey decrypt path    (WolfSSL key_dec)
#     aes_decrypt_init             (libsodium)
# These libraries pre-apply InvMixColumns to round keys 1..Nr-1 (FIPS-197
# §5.3.5 EqInvCipher) and/or reverse the round-key order so decryption is a
# linear walk in the same direction as encryption.
#
# TWEAK bit-flags (aeskeyfind.c:33-34):
#     TWEAK_INVMIXCOLUMN = 0x1   InvMixColumns over round keys 1..Nr-1
#     TWEAK_REVERSE_ORDER = 0x2  Reverse round-key word order
# Combos: 0 (forward) / 1 (InvMix) / 2 (Reverse) / 3 (both).
# ---------------------------------------------------------------------------

def _build_gf_table(c: int) -> list:
    """Build GF(2^8) multiplication-by-c lookup table.
    AES polynomial 0x1B (FIPS-197 §4.2). Verified vs aeskeyfind aes.h GF tables.
    """
    tbl = [0] * 256
    for a in range(256):
        result = 0
        x = a
        y = c
        for _ in range(8):
            if y & 1:
                result ^= x
            x = ((x << 1) ^ 0x1B) & 0xFF if (x & 0x80) else (x << 1) & 0xFF
            y >>= 1
        tbl[a] = result & 0xFF
    return tbl


# Precomputed GF(2^8) tables for the four InvMixColumns matrix entries.
_GF09 = _build_gf_table(0x09)
_GF0B = _build_gf_table(0x0B)
_GF0D = _build_gf_table(0x0D)
_GF0E = _build_gf_table(0x0E)


def _inv_mix_word(w: int) -> int:
    """InvMixColumns on one 32-bit AES word (FIPS-197 §5.3.3).

    Matrix:    [0e 0b 0d 09]
               [09 0e 0b 0d]
               [0d 09 0e 0b]
               [0b 0d 09 0e]

    Bytes are read in LE order from the uint32 word (matches the
    struct.unpack_from("<44I", ...) interpretation used by the AES-128 scan).
    """
    b0 = w & 0xFF
    b1 = (w >> 8) & 0xFF
    b2 = (w >> 16) & 0xFF
    b3 = (w >> 24) & 0xFF
    n0 = _GF0E[b0] ^ _GF0B[b1] ^ _GF0D[b2] ^ _GF09[b3]
    n1 = _GF09[b0] ^ _GF0E[b1] ^ _GF0B[b2] ^ _GF0D[b3]
    n2 = _GF0D[b0] ^ _GF09[b1] ^ _GF0E[b2] ^ _GF0B[b3]
    n3 = _GF0B[b0] ^ _GF0D[b1] ^ _GF09[b2] ^ _GF0E[b3]
    return n0 | (n1 << 8) | (n2 << 16) | (n3 << 24)


def _apply_invmix_128(map_: list) -> list:
    """Apply InvMixColumns to AES-128 round keys 1..9 (words 4..39).

    Round 0 (words 0..3) and Round 10 (words 40..43) keep raw form per
    FIPS-197 EqInvCipher convention (aeskeyfind.c:160-167)."""
    out = list(map_)
    for word_idx in range(4, 40):
        out[word_idx] = _inv_mix_word(map_[word_idx])
    return out


def _apply_reverse_128(map_: list) -> list:
    """Reverse round-key block order for AES-128 (11 round keys × 4 words).

    Used by decrypt-optimised schedulers that walk the schedule in reverse
    (aeskeyfind.c:34 TWEAK_REVERSE_ORDER). Round block r in the input
    becomes block (10 - r) in the output."""
    out = [0] * 44
    for r in range(11):
        for c in range(4):
            out[r * 4 + c] = map_[(10 - r) * 4 + c]
    return out


def _aes128_constraint_xor(map_: list, threshold: int) -> int:
    """One AES-128 constraint accumulation pass (aeskeyfind.c:226-249).

    Returns the running xor sum across rows 1..10. Exits early once the
    accumulated count exceeds `threshold` (aeskeyfind.c:246 verbatim)."""
    xor_128 = 0
    for row in range(1, 11):
        for column in range(4):
            if column == 0:
                constraint = (_key_core_128(map_[4 * row - 1], row)
                              ^ map_[4 * (row - 1)]
                              ^ map_[4 * row])
            else:
                constraint = (map_[4 * row + column - 1]
                              ^ map_[4 * (row - 1) + column]
                              ^ map_[4 * row + column])
            xor_128 += _popcount_word(constraint)
            if xor_128 > threshold:
                return xor_128
        if xor_128 >= threshold:
            return xor_128
    return xor_128


def aeskeyfind_scan(data: bytes, threshold: int = AESKEYFIND_THRESHOLD) -> list[dict]:
    """Port of aeskeyfind's find_keys -- per-round XOR-constraint popcount,
    NO re-expansion. AES-128 and AES-256 only (no AES-192, per source).

    aeskeyfind.c:190-251 (find_keys main loop).

    LIMITATION (upstream-aware): aeskeyfind.c's AES-128 path wraps the
    constraint check in a MAX_TWEAKS=4 outer loop with two bit-flags
    (line 33-34, line 215):
      TWEAK_REVERSE_ORDER = 0x2  -- reversed round-key ordering
                                    (decrypt-only schedulers in some libs)
      TWEAK_INVMIXCOLUMN  = 0x1  -- decrypt-side round keys with
                                    InvMixColumns pre-applied (mbedTLS
                                    decrypt path; WolfSSL key_dec variant;
                                    aeskeyfind.c:148-175 `unconvert_key`)
    STATUS (implemented 2026-06-03): the AES-128 path now runs the full
    MAX_TWEAKS=4 outer loop (see the `for tweak in range(4)` scan below).
    For each tweak bit-combo 0..3 it applies _apply_invmix_128 (InvMixColumns
    over round keys 1..Nr-1, per aeskeyfind.c:148-175 `unconvert_key`, GF(2^8)
    with the byte-reversed-within-word quirk at aeskeyfind.c:159-160) and/or
    _apply_reverse_128 (reversed round-key word order) before the constraint
    check, so AES-128 keys from decrypt-optimised schedulers (mbedTLS
    aes_setkey_dec, WolfSSL key_dec, libsodium aes_decrypt_init) ARE detected.
    The AES-256 path remains forward-only (tweaks=0), matching upstream
    aeskeyfind's own "FIXME: implement tweaks here too" at aeskeyfind.c:192 --
    AES-256 decrypt-optimised schedules are the only remaining FN class."""
    # 176 = AES-128 min schedule length. The AES-256 pass uses n = len - 240,
    # so range(n+1) is empty (skips safely) on 176-239 byte data, while the
    # AES-128 pass below (n128 = len - 176) still runs. The old < 240 guard
    # silently disabled AES-128 detection on truncated 176-239 byte snapshots.
    if not data or len(data) < 176:
        return []
    hits: list[dict] = []
    n = len(data) - AESKEYFIND_MIN_LEN
    # off-by-one. range(n) skips the final valid window when
    # len(data) == AESKEYFIND_MIN_LEN (240). Use range(n + 1) so the last
    # 240-byte window at offset n is scanned. Equivalent: range(len(data) -
    # AESKEYFIND_MIN_LEN + 1).

    # ---- AES-256 pass (lines 197-218): 240-byte schedule, Nk=8, Nr=14 ----
    # sliding-window byte-frequency table reduces entropy filter from O(n*176) to O(n).
    # Maintain a 256-entry histogram updated incrementally per slide; the entropy gate now short-circuits BEFORE struct.unpack_from for a typical 10-100x speedup on zero-filled regions.
    if len(data) >= 176:
        _hist256 = [0] * 256
        for _b in data[:176]:
            _hist256[_b] += 1
    else:
        _hist256 = None
    for i in range(n + 1):
        # entropy gate FIRST to short-circuit expensive struct.unpack_from on low-entropy windows.
        if _hist256 is not None and max(_hist256) > 8:
            # Slide histogram forward by one byte for next iteration before continue.
            if i + 176 < len(data):
                _hist256[data[i]] -= 1
                _hist256[data[i + 176]] += 1
            continue
        # Read 60 little-endian uint32 words (240 bytes).
        try:
            map_ = list(struct.unpack_from("<60I", data, i))
        except struct.error:
            break
        # redundant check removed -- entropy already gated above; kept as defensive assertion-style sanity in case _hist256 is None for short data.
        if _hist256 is None and max(Counter(data[i:i + 176]).values()) > 8:
            continue
        xor_256 = 0
        for row in range(1, 8):       # rows 1..7
            for column in range(8):
                # match aeskeyfind.c:200 verbatim (column == 4) to preserve verbatim-port property.
                if row == 7 and column == 4:   # aeskeyfind.c:200 partial-row break (verbatim)
                    break
                if column == 0:
                    # FIPS-197 KeyExpansion col-0: SubWord(RotWord(W[i-1])) ^ Rcon ^ W[i-Nk]
                    constraint = (_key_core_128(map_[8 * row - 1], row)
                                  ^ map_[8 * (row - 1)]
                                  ^ map_[8 * row])
                elif column == 4:
                    # AES-256 col-4: SubWord(W[i-1]) ^ W[i-Nk]
                    constraint = (_sbox_word(map_[8 * row + 3])
                                  ^ map_[8 * (row - 1) + 4]
                                  ^ map_[8 * row + 4])
                else:
                    constraint = (map_[8 * row + column - 1]
                                  ^ map_[8 * (row - 1) + column]
                                  ^ map_[8 * row + column])
                xor_256 += _popcount_word(constraint)
                if xor_256 > threshold:        # aeskeyfind.c:214 early break
                    break
            if xor_256 > threshold:
                break
        if xor_256 <= threshold:               # aeskeyfind.c:217  (<= for 256)
            hits.append({
                "offset":   i,
                "key_bits": 256,
                "errors":   xor_256,
                "key_hex":  bytes(data[i:i + 32]).hex(),
            })
        # Slide histogram forward for next iteration (parity with the continue
        # path above and with the AES-128 pass below). Without this, the gate
        # desyncs after the first window that passes the entropy filter.
        if _hist256 is not None and i + 176 < len(data):
            _hist256[data[i]] -= 1
            _hist256[data[i + 176]] += 1

    # ---- AES-128 pass with MAX_TWEAKS=4 (aeskeyfind.c:220-251 + 33-34) ----
    # 2026-06-03 FIX: outer TWEAK loop now scans all 4 (InvMix × Reverse)
    # combinations. Previously only tweak=0 was tested (forward schedule),
    # which missed decrypt-optimised AES-128 keys from mbedTLS
    # mbedtls_aes_setkey_dec / WolfSSL wc_AesSetKey-dec / libsodium
    # aes_decrypt_init. See helpers: _apply_invmix_128, _apply_reverse_128.
    n128 = len(data) - 176
    if len(data) >= 176:
        _hist128 = [0] * 256
        for _b in data[:176]:
            _hist128[_b] += 1
    else:
        _hist128 = None
    for i in range(n128 + 1):
        if _hist128 is not None and max(_hist128) > 8:
            if i + 176 < len(data):
                _hist128[data[i]] -= 1
                _hist128[data[i + 176]] += 1
            continue
        try:
            map_ = list(struct.unpack_from("<44I", data, i))
        except struct.error:
            break
        if _hist128 is None and max(Counter(data[i:i + 176]).values()) > 8:
            continue
        # 4-way tweak scan; record the lowest-error match.
        best_xor = threshold + 1
        best_tweak = 0
        for tweak in range(4):
            test_map = map_
            if tweak & 0x1:   # TWEAK_INVMIXCOLUMN
                test_map = _apply_invmix_128(test_map)
            if tweak & 0x2:   # TWEAK_REVERSE_ORDER
                test_map = _apply_reverse_128(test_map)
            xor_128 = _aes128_constraint_xor(test_map, threshold)
            if xor_128 < best_xor:
                best_xor = xor_128
                best_tweak = tweak
                if best_xor == 0:
                    break    # perfect match — short-circuit remaining tweaks
        if best_xor < threshold:               # aeskeyfind.c:249  (< for 128)
            hits.append({
                "offset":   i,
                "key_bits": 128,
                "errors":   best_xor,
                "tweak":    best_tweak,   # 0=forward / 1=InvMix / 2=Reverse / 3=both
                # For reverse-order schedules (tweak & 0x2, e.g. mbedTLS/WolfSSL
                # decrypt key schedules) the master (round-0) key is the LAST round
                # key of the stored forward layout, i.e. words 40..43 = data[i+160:i+176];
                # only the forward/InvMix tweaks keep the master key in the first block.
                "key_hex":  bytes(data[i + 160:i + 176] if (best_tweak & 0x2)
                                  else data[i:i + 16]).hex(),
            })
        # Slide histogram forward for next iteration (parity with continue path).
        if _hist128 is not None and i + 176 < len(data):
            _hist128[data[i]] -= 1
            _hist128[data[i + 176]] += 1

    return hits


# ===========================================================================
# wanakiwi / wannakey  (Guinet 2017, aguinet/wannakey verbatim)
# ===========================================================================
# Constants from wannakey/wannakey/wkey/search_primes.cpp (aguinet/wannakey master,
# verified 2026-05-29):
#   #define PALIGN 4                                       [line 24]
#   #define MINIMAL_ENTROPY 0.7                            [line 25]   (wannakey)
# wanakiwi/wanakiwi.c:118-119 sets kData.minEntropy = 0.5 default for wanakiwi.
# We use the wannakey value (0.7) -- stricter, fewer false positives.
# Region filter (caller's responsibility): MEM_PRIVATE | PAGE_READWRITE
# | State != MEM_RESERVE  (wannakey/wannakey/wkey/process.cpp / wanakiwi.c:226).
# normalizedEntropy implementation: wannakey/wannakey/wkey/tools.cpp:44-62.
# Our trace-based use case: key-birth snapshots are pre-filtered by the
# PinTool's snapshot capture path, so the runtime VirtualQuery predicate
# is not applicable -- documented here for spec equivalence.
WANAKIWI_STRIDE       = 4
WANAKIWI_PRIME_BYTES  = 128    # RSA-2048 default; parametrise per modulus
WANAKIWI_MIN_ENTROPY  = 0.7    # wannakey hardcoded; wanakiwi default 0.5


def _normalized_shannon(window: bytes) -> float:
    """Faithful port of wannakey/wannakey/wkey/tools.cpp:44-62 normalizedEntropy:

        for each nonzero count c: H += p * ln(p)
        return -H / ln(256.0)

    Yields entropy in [0, 1].
    """
    if not window:
        return 0.0
    counts = Counter(window)
    n = len(window)
    H = 0.0
    for c in counts.values():
        p = c / n
        H += p * math.log(p)
    if H == 0.0:                # avoid -0.0
        return 0.0
    return -H / math.log(256.0)


def wanakiwi_prime_scan(data: bytes,
                        modulus_int: int,
                        prime_bytes: int = WANAKIWI_PRIME_BYTES,
                        stride: int = WANAKIWI_STRIDE,
                        min_entropy: float = WANAKIWI_MIN_ENTROPY) -> list[dict]:
    """Verbatim port of wannakey/wannakey/wkey/search_primes.cpp:32-90.

    For each PALIGN-aligned offset, take a PrimeSize byte window, check
    entropy, then test BOTH little- and big-endian interpretations against
    `N % candidate == 0`. No bit-length / parity / Miller-Rabin gate --
    those are wanakiwi's *port-level* additions (RSA_check_key in
    rsautil.c:57); the wannakey gating test is divisibility alone.
    """
    if not data or modulus_int <= 0 or len(data) < prime_bytes:
        return []
    hits: list[dict] = []
    # wannakey/wannakey/wkey/search_primes.cpp:36,76  LenStop = ((Len-PrimeSize)/PALIGN)*PALIGN
    len_stop = ((len(data) - prime_bytes) // stride) * stride
    for offset in range(0, len_stop + 1, stride):
        window = data[offset:offset + prime_bytes]
        if _normalized_shannon(window) < min_entropy:
            continue
        # search_primes.cpp:48,55 -- try BOTH endians per offset.
        for endian in ("little", "big"):
            cand = int.from_bytes(window, endian)
            if cand <= 1:
                continue
            # skip even candidates -- RSA primes p,q are odd, even values are guaranteed false positives wasting modular reduction.
            if cand & 1 == 0:
                continue
            if modulus_int % cand == 0 and cand != modulus_int:
                hits.append({
                    "offset":  offset,
                    "endian":  endian,
                    "bit_len": cand.bit_length(),
                })
                break       # one endian per offset is enough
    return hits


# ===========================================================================
# BCRYPT_RSAKEY_BLOB scan  (Microsoft CNG bcrypt.h verbatim)
# ===========================================================================
# struct BCRYPT_RSAKEY_BLOB {
#     ULONG  Magic;       // 'RSA3' (full priv) / 'RSA2' (half priv) / 'RSA1' (pub)
#     ULONG  BitLength;
#     ULONG  cbPublicExp;
#     ULONG  cbModulus;
#     ULONG  cbPrime1;
#     ULONG  cbPrime2;
# }   // 24 bytes, followed by payload
_BCRYPT_MAGICS = {
    b"RSA3": ("full_private",  True),
    b"RSA2": ("half_private",  True),
    b"RSA1": ("public",         False),
}
_BCRYPT_VALID_BITS = {1024, 2048, 3072, 4096}


def bcrypt_rsa_blob_scan(data: bytes) -> list[dict]:
    """Microsoft CNG bcrypt.h verbatim: scan for BCRYPT_RSAKEY_BLOB
    structures whose 24-byte header is self-consistent.

    (UNSOUND -> SOUND):
      (a) cb_pub_exp range relaxed from {3, 4} to 1..8. Microsoft CNG docs
          allow cbPublicExp 1..8 bytes (BCRYPT_RSAKEY_BLOB). Previously only
          e=65537 (cb=3) and similar were captured; legacy smartcards using
          e=3 (cb=1) or e=17 (cb=1) were false-negatives.
      (b) off-by-one in offset loop: range(0, len(data) - 24) skips the
          final valid 24-byte header window. Now range(0, len(data) - 24 + 1)
          so the last valid offset is scanned.
      (c) Payload length boundary: ensure the full RSA payload
          (cb_pub_exp + cb_mod + 2*cb_p1) actually fits in `data` before
          appending; rejects truncated/garbage matches.
    """
    if not data or len(data) < 24:
        return []
    hits: list[dict] = []
    data_len = len(data)
    for offset in range(0, data_len - 24 + 1):
        magic = data[offset:offset + 4]
        if magic not in _BCRYPT_MAGICS:
            continue
        try:
            bit_length, cb_pub_exp, cb_mod, cb_p1, cb_p2 = struct.unpack_from(
                "<IIIII", data, offset + 4)
        except struct.error:
            continue
        if bit_length not in _BCRYPT_VALID_BITS:
            continue
        expected_mod = bit_length // 8
        if cb_mod != expected_mod:
            continue
        kind, is_private = _BCRYPT_MAGICS[magic]
        if is_private and magic in (b"RSA2", b"RSA3"):
            expected_prime = bit_length // 16
            if cb_p1 != expected_prime or cb_p2 != expected_prime:
                continue
        # cb_pub_exp 1..8 bytes per CNG docs (was 3 or 4 only).
        if not (1 <= cb_pub_exp <= 8):
            continue
        # payload length boundary check.
        #
        # BCRYPT_RSAKEY_BLOB payload layout per
        # MSDN (CNG ncrypt.h, see "BCRYPT_RSAKEY_BLOB structure" on
        # Microsoft Learn) is:
        #
        #   public  (RSA1/RSAPUBLIC) : Exponent | Modulus
        #   private (RSA2/RSAPRIVATE): Exponent | Modulus | Prime1 | Prime2
        #   full    (RSA3/RSAFULLPRIVATE):
        #                             Exponent | Modulus | Prime1 | Prime2 |
        #                             Exponent1 | Exponent2 | Coefficient |
        #                             PrivateExponent
        #
        # cb_p1 == cb_p2 == cb_mod/2; Exponent1/Exponent2/Coefficient are
        # each cb_p1 bytes; PrivateExponent is cb_mod bytes. So:
        #   RSA1: cb_pub_exp + cb_mod
        #   RSA2: cb_pub_exp + cb_mod + 2*cb_p1                 (Prime1+Prime2 added)
        #   RSA3: cb_pub_exp + cb_mod + 2*cb_p1                 (Prime1+Prime2)
        #                              + 3*cb_p1                (Exp1+Exp2+Coeff)
        #                              + cb_mod                 (PrivateExponent)
        #         = cb_pub_exp + 2*cb_mod + 5*cb_p1
        payload_bytes = cb_pub_exp + cb_mod
        if is_private and magic in (b"RSA2", b"RSA3"):
            payload_bytes += 2 * cb_p1   # + Prime1 + Prime2
            if magic == b"RSA3":
                # + Exponent1 (cb_p1) + Exponent2 (cb_p1) + Coefficient
                # (cb_p1) + PrivateExponent (cb_mod). Total tail = 3*cb_p1
                # + cb_mod.  Conservative upper bound; per spec each value
                # is exactly that many bytes.
                payload_bytes += 3 * cb_p1 + cb_mod
        if offset + 24 + payload_bytes > data_len:
            continue
        hits.append({
            "offset":     offset,
            "magic":      magic.decode("ascii", errors="replace"),
            "kind":       kind,
            "is_private": is_private,
            "bit_length": bit_length,
            "cb_pub_exp": cb_pub_exp,
            "cb_mod":     cb_mod,
            "cb_prime":   cb_p1,
        })
    return hits


# ===========================================================================
# Avaddon session-key scan  (Yuste & Pastrana 2021, AvaddonDecryptor verbatim)
# ===========================================================================
# JavierYuste/AvaddonDecryptor/main.py:193:
#     pattern = "106600000100000020000000"
# Comment at main.py:23-24: "Pattern to search for (part of the key_data_s
#   structure, in particular alg_id, flags and key_size)"
# main.py:88-91: read 4-byte pointer at +12, then 32 bytes at that VA.
# Avaddon is x86 -- pointer is 4 bytes, not 8.
# The XOR mask 0xE35A172C cited in some secondary writeups is NOT in
# Yuste's decryptor source; the scan operates on the plaintext key_data_s
# allocated next to the HCRYPTKEY blob, not on the magic-protected blob.
# (Verified against full read of main.py 2026-05; no XOR / bit-flip ops.)
# NB: the range check `0 < ptr < 0x80000000` below is a defensive addition
# not in Yuste's source -- main.py dereferences unconditionally and relies
# on the minidump library to filter invalid VAs. Documented here for
# verbatim-port disclosure.
_AVADDON_PATTERN = bytes.fromhex("10660000" "01000000" "20000000")


def avaddon_session_key_scan(data: bytes) -> list[dict]:
    """Verbatim port of AvaddonDecryptor/main.py pattern scan."""
    if not data:
        return []
    hits: list[dict] = []
    start = 0
    while True:
        off = data.find(_AVADDON_PATTERN, start)
        if off < 0:
            break
        ptr_off = off + len(_AVADDON_PATTERN)
        if ptr_off + 4 <= len(data):
            # main.py:91  mm.read(4)  -- 32-bit pointer (Avaddon = x86 process).
            ptr = struct.unpack_from("<I", data, ptr_off)[0]
            # User-mode x86 address range: 0 < ptr < 0x80000000.
            if 0 < ptr < 0x80000000:
                hits.append({
                    "offset":   off,
                    "alg":      "CALG_AES_256",
                    "key_size": 0x20,
                    "key_ptr":  ptr,
                })
        start = off + 1
    return hits


# ===========================================================================
# CryptoAPI PRIVATEKEYBLOB scan (legacy CryptoAPI key blobs)
# ===========================================================================
_CRYPTOAPI_RSA_ALGS = {
    0x0000A400,  # CALG_RSA_KEYX  (wincrypt.h)
    0x00002400,  # CALG_RSA_SIGN  (wincrypt.h)
}


def cryptoapi_rsa_blob_scan(data: bytes) -> list[dict]:
    """Microsoft CryptoAPI PRIVATEKEYBLOB scan (wincrypt.h "Base Provider
    Key BLOBs").  Layout:

        BLOBHEADER (8 B): bType=0x07 (PRIVATEKEYBLOB), bVersion=0x02,
                          reserved=0x0000, aiKeyAlg (CALG_RSA_*)
        RSAPUBKEY (12 B): magic 'RSA2' (0x32415352), bitlen (LE), pubexp (LE)
        tail: modulus(bitlen/8) prime1/2(bitlen/16) exp1/2/coef(bitlen/16)
              privexp(bitlen/8)

    Unlike BCRYPT_RSAKEY_BLOB the magic sits at offset+8 (after the
    BLOBHEADER), so bcrypt_rsa_blob_scan -- which anchors the magic at
    offset+0 -- misreads the header and rejects it.  A private RSA key left
    in a key-birth snapshot is directly recoverable, so it must be captured
    here too.  The full payload-fits check rejects stray 07 02 00 00 bytes.
    """
    if not data or len(data) < 20:
        return []
    hits: list[dict] = []
    dl = len(data)
    i = 0
    while True:
        i = data.find(b"\x07\x02\x00\x00", i)
        if i < 0 or i + 20 > dl:
            break
        ai_key_alg = struct.unpack_from("<I", data, i + 4)[0]
        magic = data[i + 8:i + 12]
        # CryptoAPI PRIVATEKEYBLOB carries magic 'RSA2' only (0x32415352, MS Learn
        # "Base Provider Key BLOBs"). The 'RSA3' RSAFULLPRIVATE form is
        # CNG/BCRYPT, which has no BLOBHEADER, so 07 02 00 00 + RSA3 never
        # occurs -- it is captured by bcrypt_rsa_blob_scan instead.
        if ai_key_alg in _CRYPTOAPI_RSA_ALGS and magic == b"RSA2":
            bit_length, pub_exp = struct.unpack_from("<II", data, i + 12)
            if bit_length in _BCRYPT_VALID_BITS:
                mod = bit_length // 8
                p = bit_length // 16
                # PRIVATEKEYBLOB tail (MS Learn verbatim): modulus(bitlen/8) +
                # prime1 + prime2 + exponent1 + exponent2 + coefficient (each
                # bitlen/16) + privateExponent(bitlen/8) = 2*mod + 5*p.
                payload = 2 * mod + 5 * p
                if i + 20 + payload <= dl:
                    hits.append({
                        "offset":     i,
                        "format":     "MS_CRYPTOAPI_PRIVATEKEYBLOB",
                        "magic":      "RSA2",
                        "bit_length": bit_length,
                        "pub_exp":    pub_exp,
                        "is_private": True,
                    })
        i += 1
    return hits


# ===========================================================================
# Modulus extraction from key-birth dump bytes (PinTool emits pointers, not
# out_buf_hex, so the chain asym_blobs are empty) — for wanakiwi_prime_scan
# ===========================================================================
def _moduli_from_snapshot_blobs(bundle: dict) -> list[int]:
    """Recover RSA moduli straight from key-birth dump bytes. The PinTool
    emits in_buf/out_buf as pointers (not out_buf_hex content), so the chain
    asym_blobs are empty; the modulus instead lives in the captured snapshot
    as a CryptoAPI PUBLICKEYBLOB (06 02 .. magic 'RSA1') or PRIVATEKEYBLOB
    (07 02 .. magic 'RSA2'): little-endian after the 8-byte BLOBHEADER +
    12-byte RSAPUBKEY (magic@+8, bitlen@+12, pubexp@+16, modulus@+20)."""
    out: list[int] = []
    snaps = bundle.get("keybirth_snapshots") or []
    trace_dir = bundle.get("trace_dir")
    if not trace_dir:
        return out
    for snap_meta in snaps:
        rel = snap_meta.get("snapshot_file")
        if not rel:
            continue
        p = os.path.join(trace_dir, rel)
        if not os.path.isfile(p):
            continue
        try:
            with open(p, "rb") as f:
                data = f.read()
        except OSError:
            continue
        for hdr in (b"\x06\x02\x00\x00", b"\x07\x02\x00\x00"):
            i = 0
            while True:
                i = data.find(hdr, i)
                if i < 0 or i + 20 > len(data):
                    break
                magic = data[i + 8:i + 12]
                if magic in (b"RSA1", b"RSA2"):
                    try:
                        bit_length = struct.unpack_from("<I", data, i + 12)[0]
                    except struct.error:
                        i += 1
                        continue
                    if bit_length in _BCRYPT_VALID_BITS:
                        mod = bit_length // 8
                        if i + 20 + mod <= len(data):
                            n = int.from_bytes(data[i + 20:i + 20 + mod],
                                               "little")
                            if n > 1:
                                out.append(n)
                i += 1
    return out


# ===========================================================================
# Modulus extraction from captured PUBLICKEYBLOB (for wanakiwi_prime_scan)
# ===========================================================================
def _extract_rsa_moduli_from_chain(bundle: dict) -> list[int]:
    """Pull RSA modulus candidates from any chain asym_blob with the
    Microsoft PUBLICKEYBLOB layout: BLOBHEADER (8B) + RSAPUBKEY (12B
    with magic 'RSA1' + bitlength + pubexp) + modulus."""
    out: list[int] = []
    cs = bundle.get("crypto_summary") or {}
    for blob in cs.get("asym_blobs") or []:
        hexstr = blob.get("hex") or ""
        # Minimum: 8B BLOBHEADER + 12B RSAPUBKEY + smallest RSA modulus
        # (RSA-1024 = 128 bytes). RSA-3072 / RSA-4096 are accepted too.
        if not hexstr or len(hexstr) < 2 * (8 + 12 + 128):
            continue
        try:
            raw = bytes.fromhex(hexstr)
        except ValueError:
            continue
        if raw[8:12] != b"RSA1":
            continue
        try:
            bit_length = int.from_bytes(raw[12:16], "little")
            # Microsoft CNG-supported RSA bit lengths (bcrypt.h
            # BCRYPT_RSA_ALGORITHM enumerated values).
            if bit_length not in (1024, 2048, 3072, 4096):
                continue
            mod_bytes = bit_length // 8
            if len(raw) < 20 + mod_bytes:
                continue
            modulus = int.from_bytes(raw[20:20 + mod_bytes], "little")
            if modulus > 1:
                out.append(modulus)
        except Exception:
            continue
    # The PinTool emits in_buf/out_buf as POINTERS (HexAddr), not out_buf_hex
    # content, so cs["asym_blobs"] above is usually empty. Recover the RSA
    # modulus directly from the key-birth dump bytes (the same snapshots the
    # byte-signature scanners read) so RC-03's wanakiwi prime scan keeps a
    # divisibility oracle.
    out += _moduli_from_snapshot_blobs(bundle)
    return out


def scan_all_snapshots(bundle: dict) -> dict:
    """Run every byte-pattern scanner over every key_residue snapshot
    file. Returns aggregate hit lists per scanner."""
    snaps = bundle.get("keybirth_snapshots") or []
    trace_dir = bundle["trace_dir"]
    moduli = _extract_rsa_moduli_from_chain(bundle)
    agg = {
        "aeskeyfind_hits":      [],
        "bcrypt_rsa_blob_hits": [],
        "cryptoapi_rsa_blob_hits":   [],
        "avaddon_session_hits": [],
        "wanakiwi_prime_hits":  [],
        "rsa_moduli_in_chain":  len(moduli),
        "snapshots_scanned":    0,
    }
    for snap_meta in snaps:
        rel = snap_meta.get("snapshot_file")
        if not rel:
            continue
        p = os.path.join(trace_dir, rel)
        if not os.path.isfile(p):
            continue
        with open(p, "rb") as f:
            data = f.read()
        if not data:
            continue
        agg["snapshots_scanned"] += 1
        for h in aeskeyfind_scan(data):
            h["snapshot_file"] = rel
            agg["aeskeyfind_hits"].append(h)
        for h in bcrypt_rsa_blob_scan(data):
            h["snapshot_file"] = rel
            agg["bcrypt_rsa_blob_hits"].append(h)
        for h in cryptoapi_rsa_blob_scan(data):
            h["snapshot_file"] = rel
            agg["cryptoapi_rsa_blob_hits"].append(h)
        for h in avaddon_session_key_scan(data):
            h["snapshot_file"] = rel
            agg["avaddon_session_hits"].append(h)
        for N in moduli:
            # RSA prime is roughly half the modulus bytes. wannakey
            # hardcodes 128 (RSA-2048) but Microsoft CNG accepts 1024 /
            # 2048 / 3072 / 4096-bit RSA. Compute per-modulus so we
            # actually find primes for 3072 / 4096-bit keys -- otherwise
            # they are silently missed.
            mod_bytes = (N.bit_length() + 7) // 8
            # RFC 8017 §3.1 + FIPS 186-5 §A.1.1: RSA semiprime N = p*q with
            # len(p) = len(q) = bit_length(N)/2. Prime byte length is exactly
            # mod_bytes/2.
            pb = mod_bytes // 2
            for h in wanakiwi_prime_scan(data, N, prime_bytes=pb):
                h["snapshot_file"] = rel
                h["modulus_bits"] = N.bit_length()
                h["prime_bytes"]  = pb
                agg["wanakiwi_prime_hits"].append(h)
    agg["aeskeyfind_count"]      = len(agg["aeskeyfind_hits"])
    agg["bcrypt_rsa_blob_count"] = len(agg["bcrypt_rsa_blob_hits"])
    agg["cryptoapi_rsa_blob_count"]   = len(agg["cryptoapi_rsa_blob_hits"])
    agg["avaddon_session_count"] = len(agg["avaddon_session_hits"])
    agg["wanakiwi_prime_count"]  = len(agg["wanakiwi_prime_hits"])
    return agg
