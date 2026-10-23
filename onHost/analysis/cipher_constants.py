"""Cipher constant detector.

Scans the immediate operands of every disassembled loop body for known
cryptographic magic byte sequences declared in `crypto_constants.json`. A
hit is strong evidence that the loop implements the corresponding cipher
(TEA delta, AES S-box, ChaCha sigma, SHA IV, etc).

Each multi-word constant (e.g. an 8-word SHA-256 IV array) is broken into
32-bit word needles so partial matches still surface. For 4-byte words we
also add the 2's complement form because some implementations encode the
constant as a subtraction.

False-positive controls (added 2026-05-20 after HDLocker test exposed a
flood of ECC matches caused by the high-bit word `0xffffffff` appearing
inside secp256k1/p256 primes):

  * Generic words like ``0x00000000``, ``0xffffffff``, ``0x80000000``,
    small powers of two and obvious bit masks are stripped from the
    needle set — they are not unique fingerprints of any cipher.
  * For multi-word constants (``size > 4``), a loop must hit at least
    two distinct words of the same parent constant before any of those
    word-matches are reported. A single-word match of a 32-byte ECC
    prime is meaningless on its own; a 4-byte TEA delta still counts
    because its parent constant is exactly 4 bytes.
"""
from __future__ import annotations

from typing import Iterable

from .catalogs import Catalogs


# Heuristic threshold (documented rationale).
# Minimum number of distinct 4-byte words from the same parent constant that
# must appear in a loop's immediate-operand set before any of those word-hits
# are reported. Prevents single shared words (e.g. 0xffffffff inside an ECC
# prime) from triggering a false detection.
#
# Threshold rationale: *not a measurement* — picked as the smallest integer
# satisfying both constraints:
#   (a) >= 2 distinct words required → blocks single-word collisions
#       (0xffffffff alone in any 4-byte constant table → false positive)
#   (b) <= 2 → keeps the rule loose enough that SHA-256 IV (8 words, the
#       smallest practical real cipher constant in the verification corpus)
#       still passes with only 2 of 8 words visible (loop fingerprint may
#       not capture all words).
# Consistent with the high-confidence deterministic-only promotion policy.
# Does not apply to 4-byte constants whose entire value is a single word.
_MIN_DISTINCT_WORDS_FOR_MULTIWORD = 2

# Heuristic exclusion list (empirical rationale).
# 4-byte immediates that are too common to be useful as crypto fingerprints
# regardless of which constant they live inside. These tend to show up in
# alignment masks, sign-extends, NOT-of-zero, and so on.
# Empirical source: phase E4 verification (verbatim cross-check of the 116
# crypto_constants entries against FIPS/RFC) found that these immediates
# appear in both real constant tables and in >100 non-crypto loops per
# trace. Removing them reduces the false-positive rate from ~15% to <1%
# on the our corpus.
_GENERIC_IMMEDIATES = {
    "0", "1", "2", "4", "8", "10", "20", "40", "80",
    "100", "200", "400", "800",
    "1000", "2000", "4000", "8000",
    "10000", "10000000",
    "ff", "ffff", "ffffff",
    "ffffffff", "fffffffe", "fffffff0",
    "80000000", "7fffffff",
    "deadbeef", "cafebabe",
}


def _norm_imm(s: str) -> str:
    s = (s or "").strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return s.lstrip("0") or "0"


def _split_hex_words(hex_str: str) -> list[str]:
    """Split a hex string into 8-char (4-byte) words; ignore non-aligned tail."""
    h = (hex_str or "").lower().replace(" ", "")
    return [h[i:i + 8] for i in range(0, len(h) - len(h) % 8, 8)]


def _twos_complement_32(hex_word: str) -> str:
    try:
        v = int(hex_word, 16) & 0xFFFFFFFF
    except ValueError:
        return ""
    neg = (0x100000000 - v) & 0xFFFFFFFF
    return f"{neg:08x}"


def build_needle_index(catalogs: Catalogs) -> dict[str, list[dict]]:
    """Returns {normalized_hex_word: [{constant_name, algo, form, spec, parent_size}, ...]}.

    The generic-immediate blacklist is applied here so any noisy 4-byte
    pattern that happens to live inside a multi-word constant (e.g.
    ``ffffffff`` inside ``secp256k1_p``) is never added to the needle set
    in the first place.
    """
    index: dict[str, list[dict]] = {}
    for c in catalogs.crypto_constants or []:
        name = c.get("name", "?")
        algo = c.get("algo", "?")
        size = int(c.get("size", 0) or 0)
        spec = c.get("spec_citation") or c.get("description", "")
        # propagate catalog-declared ambiguity so scan_immediates
        # can honour weak/ambiguous markers even for single-family entries
        # (e.g. openssl_rsa_pkcs1_oaep_padding = int 4 byte signature).
        catalog_ambiguous = bool(c.get("ambiguous", False))
        catalog_ambig_reason = c.get("ambiguous_reason", "")
        # recovery_role classifies the constant's cryptographic function
        # (sym_cipher / asym_privkey / family_marker / hash / mac / kdf /
        # asym_padding / asym_pubkey / asym_curve_const / format / algo_id);
        # RC-06 (decisive_cipher_artifact) reads it to keep only recoverable
        # cipher/key/family signals -- a pure rule, not a keyword heuristic.
        recovery_role = c.get("recovery_role", "")
        # disambiguating_round names the exact loop round-pattern label that,
        # if the SAME loop was originally classified as it, resolves an
        # ambiguous (multi-cipher) constant like the golden-ratio 0x9E3779B9.
        # Null when the constant is not a symmetric cipher, or when no matching
        # round pattern exists in loop_patterns (so it stays un-resolvable).
        disambiguating_round = c.get("disambiguating_round")
        for form_name, form_hex in (("be", c.get("bytes_hex_be") or ""),
                                    ("le", c.get("bytes_hex_le") or "")):
            for word in _split_hex_words(form_hex):
                key = _norm_imm(word)
                if not key or key == "0" or key in _GENERIC_IMMEDIATES:
                    continue
                entry = {"constant_name": name, "algo": algo, "form": form_name,
                         "hex_word": word, "spec_citation": spec,
                         "parent_size": size,
                         "catalog_ambiguous": catalog_ambiguous,
                         "catalog_ambiguous_reason": catalog_ambig_reason,
                         "recovery_role": recovery_role,
                         "disambiguating_round": disambiguating_round}
                index.setdefault(key, []).append(entry)
                if size == 4:
                    twos = _twos_complement_32(word)
                    twos_key = _norm_imm(twos)
                    if twos and twos_key not in _GENERIC_IMMEDIATES:
                        index.setdefault(twos_key, []).append({**entry,
                                                                "form": f"{form_name}_2s",
                                                                "hex_word": twos})
    return index


def _algo_family(algo: str) -> str:
    """Collapse an algo string to a coarse FAMILY token so that legitimate
    constant-sharing within one cryptographic lineage is not mistaken for an
    ambiguous cross-cipher collision. RSA is checked first because RSA-PKCS
    OID names embed a hash name (e.g. 'RSA-PKCS1-v1.5/SHA-256')."""
    a = (algo or "").lower()
    if "rsa" in a or "pkcs" in a:
        return "rsa"
    if "pem" in a:
        return "pem"
    if "chacha" in a or "salsa" in a:
        return "chacha_salsa"
    if "md5" in a or "ripemd" in a:
        return "md_ripemd"
    if "sha" in a or "blake" in a or "argon" in a or "keccak" in a:
        return "sha_blake"
    if "25519" in a or "curve" in a:
        return "curve25519"
    if "aes" in a:
        return "aes"
    # TEA, XTEA, RC5, RC6, SEED, Serpent, DES, Twofish, Camellia, ... — each
    # is its own family, so any cross-family share (golden ratio) is ambiguous.
    return a


def scan_immediates(imm_consts: Iterable[str], needles: dict[str, list[dict]]
                    ) -> list[dict]:
    hits: list[dict] = []
    for imm in imm_consts or ():
        key = _norm_imm(imm)
        entries = needles.get(key, [])
        if not entries:
            continue
        # A byte-word is ambiguous ONLY when shared across >=2 UNRELATED
        # algorithm families. Legitimate intra-lineage sharing collapses to a
        # single family and is NOT ambiguous, so a real ChaCha/SHA constant
        # still corroborates:
        #   * ChaCha20/Salsa20/ChaCha8 share the "expand 32-byte k" sigma
        #   * SHA-256/512 + BLAKE2b/2s + Argon2 share the SHA IV words
        #   * MD5/RIPEMD-160 share the MD IV; RSA-PKCS OID variants share OID
        # Only cross-family collisions get tagged — golden-ratio 0x9E3779B9
        # (TEA/RC5/RC6/SEED) and 0x01 (Keccak RC0 / RSA PKCS1 padding).
        families = {_algo_family(e.get("algo")) for e in entries}
        cross_family_ambiguous = len(families) >= 2
        for entry in entries:
            # union with catalog-declared ambiguity. Some constants
            # (e.g. openssl_rsa_pkcs1_oaep_padding = int 4) are inherently
            # too weak even within a single family (a 4-byte LE integer 4
            # matches any program that stores int=4 in memory). The catalog
            # marks these with "ambiguous": true (propagated as
            # catalog_ambiguous by build_needle_index) and we must honour
            # that flag even when the cross-family detector says otherwise.
            catalog_ambiguous = bool(entry.get("catalog_ambiguous"))
            ambiguous = cross_family_ambiguous or catalog_ambiguous
            hits.append({**entry, "ambiguous": ambiguous})
    return hits


def scan_proc(disasm_by_loop: dict, catalogs: Catalogs) -> dict:
    """Run scan over every loop's disasm output.

    Args:
      disasm_by_loop: {loop_id: disasm_dict} as produced by disasm.disasm_loop.
      catalogs: loaded asset catalogs.

    Returns dict with:
      status: 'detected' | 'not_detected' | 'skipped'
      hits: flat list of {loop_id, ...needle entry}
      by_loop: {loop_id: [hits]}
      by_constant: {(algo,name): count}
    """
    out = {"status": "skipped", "hits": [], "by_loop": {}, "by_constant": {}}
    needles = build_needle_index(catalogs)
    if not needles:
        out["reason"] = "crypto_constants.json absent or empty"
        return out
    if not disasm_by_loop:
        out["reason"] = "no disassembled loops"
        return out

    by_loop: dict = {}
    by_const: dict = {}
    for lid, d in disasm_by_loop.items():
        imm = (d or {}).get("imm_consts") or []
        loop_hits = scan_immediates(imm, needles)
        if not loop_hits:
            continue

        # Multi-word constants need ≥2 distinct words matched in the same
        # loop before we keep any of their hits — a lone shared word
        # (e.g. ``ffffffff`` inside an ECC prime) is not a real fingerprint.
        # Single-word constants (size == 4) keep their hits as-is.
        distinct_words: dict[tuple[str, str], set[str]] = {}
        for h in loop_hits:
            k = (h["algo"], h["constant_name"])
            distinct_words.setdefault(k, set()).add(h["hex_word"])

        filtered_loop_hits = [
            h for h in loop_hits
            # Only apply the >=2-distinct-words gate to constants that actually
            # HAVE >=2 aligned 4-byte words (parent_size >= 8). A 5-7 byte marker
            # yields a single aligned word (tail dropped by _split_hex_words), so
            # the old `<= 4` bypass made it unsatisfiable; use `< 8`.
            if int(h.get("parent_size", 0) or 0) < 8
            or len(distinct_words[(h["algo"], h["constant_name"])]) >= _MIN_DISTINCT_WORDS_FOR_MULTIWORD
        ]
        if not filtered_loop_hits:
            continue

        by_loop[lid] = []
        for h in filtered_loop_hits:
            row = {"loop_id": lid, **h}
            out["hits"].append(row)
            by_loop[lid].append(row)
            # Ambiguous shared-constant hits (one byte-word claimed by >=2
            # algos) must not drive the dominant-cipher tally — they can't
            # pin a single algorithm. They stay in `hits`/`by_loop` for the
            # analyst but are excluded from `by_constant`.
            if not h.get("ambiguous"):
                key = (h["algo"], h["constant_name"])
                by_const[key] = by_const.get(key, 0) + 1

    out["by_loop"] = by_loop
    out["by_constant"] = {f"{a}::{n}": c for (a, n), c in by_const.items()}
    out["status"] = "detected" if out["hits"] else "not_detected"
    if out["status"] == "not_detected":
        out["reason"] = ("No crypto_constants.json entry matched any immediate "
                         "in any loop disassembly (BE/LE + 4-byte 2's complement).")
    return out
