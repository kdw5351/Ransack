"""Step 3 cross-axis corroboration (paper §III — stage 3 of the four
host-side analysis stages).

Each loop is independently labelled by the pattern matcher (Step 2,
`loop_classifier.py`). That label is a *proposal* based on structural shape
alone. Step 3 then joins three orthogonal evidence streams to either
confirm the proposal with high confidence, leave it as a pattern-only
guess, or downgrade it to `unknown.utility` when the co-located evidence
contradicts the structural match.

Three evidence streams per loop:

  S1  pattern        — the loop_classifier label (already family-tagged via
                       label prefix, e.g. `crypto.aes_round` → AES)
  S2  crypto-API     — crypto_summary.per_loop[lid] histograms; if a
                       BCryptEncrypt / EVP_AES_* / TEA-specific routine
                       fired from inside this loop's IP range, the
                       PinTool tagged the event with loop_id == lid
  S3  byte-constant  — cipher_constants.by_loop[lid] hits; a TEA delta
                       immediate, an AES S-box word, a SHA IV, etc.

Outcome matrix (S1 says cipher X):

  +-----------+---------+--------------+---------------------------------+
  | S2 says X | S3 says X | verdict    | label transformation            |
  +-----------+---------+--------------+---------------------------------+
  |   yes     |   yes   | corroborated | keep label, conf unchanged      |
  |   yes     |   no    | corroborated | keep label, conf unchanged      |
  |   no      |   yes   | byte_gated   | keep label, conf unchanged      |
  |   no      |   no    | pattern_only | keep label, conf unchanged      |
  |   no      |   ≠ X   | downgraded   | label → unknown.utility,        |
  |           |         |              | reason recorded                 |
  +-----------+---------+--------------+---------------------------------+

A downgrade is triggered only by S3 -- a byte-constant that names a
*different* cipher -- and only when neither axis corroborates X. The S2
crypto-API stream is used to corroborate a label, never on its own to
downgrade it.

A non-crypto label (e.g. `memory.bitfield_assemble`, `control.add_pop_*`)
never enters Step 3 — the corroboration is only meaningful for proposals
that claim a specific cipher.

For loops that show *strong* key-axis or byte-axis evidence even though
the pattern matcher returned `unknown.utility`, this module also surfaces
an `unlabelled_evidence` block so the analyst can see those loops without
silently inventing a label outside the published pattern catalogue.
"""
from __future__ import annotations



# ---------------------------------------------------------------------------
# Label → expected cipher family
# ---------------------------------------------------------------------------
# Keys are matched as a suffix of the dotted label after the `crypto.`
# prefix. The family token must match (case-insensitive substring) at
# least one of the API names in S2 or the algo string of an S3 hit for
# the label to be corroborated.

LABEL_TO_FAMILY: dict[str, list[str]] = {
    # Symmetric block ciphers
    "aes_round":             ["aes"],
    "aes_tt":                ["aes"],
    "aes_ni":                ["aes"],
    "aes_software_sbox":     ["aes"],
    "aes_mixcolumns":        ["aes"],
    "aes_keyschedule":       ["aes"],
    "des_round":             ["des"],
    "des_feistel_round":     ["des"],
    "tea_round":             ["tea"],
    "xtea_round":            ["tea", "xtea"],
    "xxtea_round":           ["tea", "xxtea"],
    "blowfish_round":        ["blowfish"],
    "rc5_round":             ["rc5"],
    "rc6_round":             ["rc6"],
    "twofish_round":         ["twofish"],
    "serpent_round":         ["serpent"],
    "camellia_round":        ["camellia"],
    # Stream ciphers
    "chacha_round":          ["chacha"],
    "chacha_quarter":        ["chacha"],
    "chacha20":              ["chacha"],
    "salsa_round":           ["salsa"],
    "salsa20_quarter":       ["salsa"],
    "rc4_round":             ["rc4", "arc4"],
    "xor_stream":            [],   # generic; corroborate by any sym_enc
    "xor_rotate":            [],
    "xor_chain_double":      [],
    "xor_pointer_walk_double": [],
    # Hashes
    "sha_round":             ["sha"],
    "sha2_round":            ["sha"],
    "sha256_round":          ["sha"],
    "sha512_round":          ["sha"],
    "md5_round":             ["md5"],
    "blake_round":           ["blake"],
    "hmac_ipad_opad":        ["hmac", "sha", "md5"],
    # CRC32 is structural-only (no cipher family); leave empty so any
    # crypto signal corroborates and S3 mismatches do not downgrade it.
    "crc32_table":           [],
    # Public-key / EC
    "bignum_loop":           ["rsa", "ecc", "curve25519", "ed25519",
                              "secp", "p256", "p384", "p521"],
    "bignum_modexp":         ["rsa", "ecc", "curve25519", "ed25519",
                              "secp", "p256", "p384", "p521"],
    "bignum_montgomery":     ["rsa", "ecc", "curve25519", "ed25519",
                              "secp", "p256", "p384", "p521"],
    "rsa_modexp":            ["rsa"],
    "ec_doubleadd":          ["ecc", "secp", "p256", "ed", "curve25519"],
    # Generic; suffix-fallback only if not above
}


# Generic crypto.* labels for which S2/S3 corroboration is permissive —
# any sym_enc/keygen event in the same loop counts. These cover families
# where the structural pattern matcher can't pin down a specific cipher.
GENERIC_CRYPTO_LABELS = {"crypto.xor_stream", "crypto.xor_rotate",
                          "crypto.xor_chain_double",
                          "crypto.xor_pointer_walk_double",
                          "crypto.crc32_table",
                          "crypto.generic"}


# ---------------------------------------------------------------------------
# S2 — process-level fallback by kind
# ---------------------------------------------------------------------------
# The PinTool emits a per-loop IP for every crypto event, but the IP lands
# inside the system DLL implementing the API (bcrypt.dll, advapi32, …),
# never inside the user-code loop range that called it. Containment by IP
# therefore cannot bridge a user-code loop to its API event — `per_loop`
# stays empty across virtually every real ransomware trace we have measured
# (Locky=609/609 orphan, Crypt888=182/182, DarkPower=11/11, Pitou=7/7).
#
# Per-loop attribution is the strong corroboration. When it fails, the
# process-wide crypto-event kind histogram is a weaker but still valid
# corroboration: if the process called sym_enc APIs at all, then a loop
# labelled `crypto.aes_software_sbox` is operating in a process that did
# do symmetric encryption. The map below records which `kind` buckets are
# spec-consistent with which cipher families.
KIND_TO_FAMILY_AFFINITY: dict[str, set[str]] = {
    # Symmetric encrypt / keygen / kdf — corroborates any block/stream cipher.
    "sym_enc":    {"aes", "des", "tea", "xtea", "xxtea", "blowfish",
                    "rc4", "arc4", "rc5", "rc6", "twofish", "serpent",
                    "camellia", "chacha", "salsa"},
    "keygen":     {"aes", "des", "tea", "xtea", "xxtea", "blowfish",
                    "rc4", "arc4", "rc5", "rc6", "twofish", "serpent",
                    "camellia", "chacha", "salsa"},
    "kdf":        {"aes", "des", "blowfish", "chacha", "salsa", "hmac",
                    "sha", "md5"},
    "key_import": {"aes", "des", "tea", "xtea", "xxtea", "blowfish",
                    "rc4", "arc4", "rc5", "rc6", "twofish", "serpent",
                    "camellia", "chacha", "salsa", "rsa", "ecc",
                    "curve25519", "ed25519", "secp", "p256", "p384",
                    "p521"},
    "key_export": {"rsa", "ecc", "curve25519", "ed25519", "secp",
                    "p256", "p384", "p521"},
    "asym_enc":   {"rsa", "ecc", "curve25519", "ed25519", "secp",
                    "p256", "p384", "p521"},
    # Hashes — corroborate hash labels and HMAC.
    "hash":       {"sha", "md5", "blake", "hmac"},
    "rand":       set(),   # RNG output alone does not pin a cipher family.
}


def _s2_process_supports_family(crypto_global: dict | None,
                                  families: list[str]) -> tuple[bool, list[str]]:
    """Process-level S2 fallback. Returns (ok, matched_kinds).
    Empty `families` (generic crypto.*) — True if any crypto kind fired."""
    if not crypto_global:
        return False, []
    by_kind = crypto_global.get("by_kind") or {}
    if not by_kind:
        return False, []
    if not families:
        # Any crypto-kind event in the process corroborates a generic label.
        crypto_kinds = {"sym_enc", "asym_enc", "hash", "keygen", "kdf",
                         "key_import", "key_export"}
        matched = [k for k in by_kind if k in crypto_kinds and (by_kind.get(k) or 0) > 0]
        return bool(matched), matched
    fam_set = set(families)
    matched: list[str] = []
    for kind, count in by_kind.items():
        if not count:
            continue
        affine = KIND_TO_FAMILY_AFFINITY.get(kind)
        if affine is None:
            continue
        if fam_set & affine:
            matched.append(kind)
    return bool(matched), sorted(matched)


def _expected_families(label: str) -> list[str]:
    """Returns the cipher-family tokens we expect to see in S2/S3 for a
    label. An empty list means "any crypto evidence counts" (the loop is
    crypto-flagged generically; the matcher can't narrow it further)."""
    if not label or not label.startswith("crypto."):
        return []
    suffix = label.split(".", 1)[1]  # drop leading "crypto."
    # Strip trailing digits (e.g. aes_round2 -> aes_round); note a "_vN"
    # suffix keeps its "v" (rstrip stops at the first non-digit/underscore).
    base = suffix.rstrip("_0123456789")
    return LABEL_TO_FAMILY.get(base, LABEL_TO_FAMILY.get(suffix, []))


# ---------------------------------------------------------------------------
# S2 — crypto-API evidence per loop
# ---------------------------------------------------------------------------

def _s2_family_tokens(per_loop_slot: dict | None) -> set[str]:
    """All API names + DLL bases that the PinTool attributed to this loop,
    folded to lowercase. The caller substring-matches expected family
    tokens against this set."""
    if not per_loop_slot:
        return set()
    out: set[str] = set()
    for name in (per_loop_slot.get("by_api") or {}):
        out.add(str(name).lower())
    for name in (per_loop_slot.get("by_dll") or {}):
        out.add(str(name).lower())
    return out


def _s2_supports_family(per_loop_slot: dict | None,
                         families: list[str]) -> tuple[bool, list[str]]:
    """For an empty `families` list (generic crypto.*) return True if any
    sym_enc/keygen/kdf event was tagged to this loop."""
    if not per_loop_slot:
        return False, []
    tokens = _s2_family_tokens(per_loop_slot)
    if not families:
        # Generic: any crypto-kind event with a tagged loop_id counts.
        crypto_calls = int(per_loop_slot.get("crypto_calls") or 0)
        return crypto_calls > 0, []
    hits = [f for f in families if any(f in t for t in tokens)]
    return bool(hits), hits


# ---------------------------------------------------------------------------
# S3 — byte-constant gate per loop
# ---------------------------------------------------------------------------

def _s3_supports_family(loop_hits: list[dict] | None,
                         families: list[str]) -> tuple[bool, list[str]]:
    """A cipher_constants hit corroborates when its `algo` string contains
    one of the expected family tokens. For generic labels (`families=[]`)
    *any* hit corroborates.

    Ambiguous hits — a byte-word shared by >=2 algorithms (e.g. the
    golden-ratio 0x9E3779B9 used by TEA/RC5/RC6/SEED/Serpent) — are NOT a
    reliable fingerprint of any single cipher, so they are excluded and can
    never byte-gate a specific label on their own."""
    if not loop_hits:
        return False, []
    concrete = [h for h in loop_hits if not h.get("ambiguous")]
    if not concrete:
        return False, []
    if not families:
        return True, list({h.get("algo", "") for h in concrete})
    matched = set()
    for h in concrete:
        algo = (h.get("algo") or "").lower()
        for f in families:
            if f in algo:
                matched.add(h.get("algo"))
                break
    return bool(matched), sorted(matched)


def _s3_other_family(loop_hits: list[dict] | None,
                      families: list[str]) -> list[str]:
    """Byte-constant hits whose algo DISAGREES with the pattern label.
    Returns the offending algo strings — used by the downgrade rule."""
    if not loop_hits or not families:
        return []
    # Collapse the expected families to coarse cipher lineages so that a hit within
    # the SAME lineage is not counted as a disagreement. Salsa20 and ChaCha20 share
    # the "expand 32-byte k" LE sigma immediates (only a ChaCha20 catalog entry
    # stores the LE-dword form), so a ChaCha20 constant hit on a Salsa20 loop is
    # agreement, not a cross-cipher conflict, and must not downgrade the label.
    from .cipher_constants import _algo_family
    fam_collapsed = {_algo_family(f) for f in families}
    other: set[str] = set()
    for h in loop_hits:
        # Ambiguous cross-family constants (e.g. golden-ratio 0x9E3779B9 shared by
        # TEA/RC5/RC6/Serpent/SEED) cannot name a single cipher, so they must NOT be
        # treated as a disagreeing algo that downgrades an otherwise-valid label.
        if h.get("ambiguous"):
            continue
        algo = (h.get("algo") or "").lower()
        if any(f in algo for f in families):
            continue
        if _algo_family(algo) in fam_collapsed:
            continue
        other.add(h.get("algo"))
    return sorted(other)


# ---------------------------------------------------------------------------
# Corroboration driver
# ---------------------------------------------------------------------------

def corroborate(loop_labels: dict[int, dict],
                 crypto_per_loop: dict[int, dict] | None,
                 cipher_const_by_loop: dict[int, list[dict]] | None,
                 crypto_global: dict | None = None) -> dict:
    """Mutates loop_labels in place. Each label entry gains:
        corroboration: {
            verdict:     'corroborated' | 'byte_gated' | 'pattern_only'
                       | 'downgraded' | 'not_applicable',
            s2_hits:     [family tokens matched in crypto-API stream],
            s3_hits:     [algo strings matched in byte-constant stream],
            s2_other:    [crypto-API families seen but unexpected],
            s3_other:    [byte-constant algos seen but unexpected],
            note:        free-text reason,
            original_label:      <pre-corroboration label, only on downgrade>,
            original_confidence: <pre-corroboration confidence, idem>
        }

    `crypto_global` is the whole-process `crypto_summary.summarize()` result
    (the same dict whose `per_loop` slot is split into `crypto_per_loop`).
    It is consulted only when per-loop S2 attribution turned up empty for
    a given loop, and provides a weaker process-level family-affinity
    corroboration (verdict still `corroborated`, note marks it `S2-process`
    rather than `S2-loop`). See the module-level comment on
    KIND_TO_FAMILY_AFFINITY for the rationale.

    Returns aggregate counters for the report.
    """
    crypto_per_loop = crypto_per_loop or {}
    cipher_const_by_loop = cipher_const_by_loop or {}
    crypto_global = crypto_global or {}

    verdict_counts = {
        "corroborated":   0,
        "byte_gated":     0,
        "pattern_only":   0,
        "downgraded":     0,
        "not_applicable": 0,
    }
    downgrades: list[dict] = []
    unlabelled_evidence: list[dict] = []

    for lid, cls in loop_labels.items():
        label = cls.get("label") or ""
        s2 = crypto_per_loop.get(lid) or {}
        s3_list = cipher_const_by_loop.get(lid) or []

        # Non-crypto labels never enter Step 3, but if the key/byte streams
        # carry evidence anyway we surface the loop for analyst review.
        if not label.startswith("crypto."):
            cls["corroboration"] = {"verdict": "not_applicable",
                                     "s2_hits": [], "s3_hits": [],
                                     "s2_other": [], "s3_other": [],
                                     "note": "non-crypto pattern label"}
            verdict_counts["not_applicable"] += 1
            if s2.get("crypto_calls") or s3_list:
                unlabelled_evidence.append({
                    "loop_id": lid, "pattern_label": label,
                    "crypto_calls": int(s2.get("crypto_calls") or 0),
                    "byte_const_hits": [h.get("algo") for h in s3_list],
                })
            continue

        # The label proposes a specific cipher family.
        families = _expected_families(label)
        s2_ok, s2_hits = _s2_supports_family(s2, families)
        s2_source = "loop" if s2_ok else None
        # Per-loop S2 missed (the typical case — see KIND_TO_FAMILY_AFFINITY
        # comment): fall back to process-level crypto-kind affinity.
        if not s2_ok:
            s2_ok, s2_hits = _s2_process_supports_family(crypto_global, families)
            if s2_ok:
                s2_source = "process"
        s3_ok, s3_hits = _s3_supports_family(s3_list, families)
        s3_other = _s3_other_family(s3_list, families) if families else []

        # Hard downgrade: byte-constant gate detected a DIFFERENT cipher
        # in this very loop and there is no S2 confirmation of the
        # pattern's claim. The byte evidence is concrete spec-cited bytes
        # so it trumps the structural guess.
        hard_downgrade = (bool(s3_other) and not s3_ok and not s2_ok
                           and label not in GENERIC_CRYPTO_LABELS)
        if hard_downgrade:
            downgrades.append({
                "loop_id": lid, "from_label": label,
                "from_confidence": cls.get("confidence"),
                "reason": (f"byte-constant gate matched {s3_other!r} but "
                            f"label expected {families!r}; "
                            f"no crypto-API event corroborated either."),
                "s3_other": s3_other,
            })
            cls["corroboration"] = {
                "verdict": "downgraded",
                "s2_hits": [], "s3_hits": [], "s2_other": [],
                "s3_other": s3_other,
                "note": "byte-constant gate disagreed with pattern label",
                "original_label": label,
                "original_confidence": cls.get("confidence"),
            }
            cls["label"]      = "unknown.utility"
            cls["category"]   = "fallback"
            cls["confidence"] = 0.0
            verdict_counts["downgraded"] += 1
            continue

        # Assign verdict label per paper §III. Confidence unchanged.
        if s2_ok and s3_ok:
            verdict = "corroborated"
        elif s2_ok:
            verdict = "corroborated"
        elif s3_ok:
            verdict = "byte_gated"
        else:
            verdict = "pattern_only"

        cls["corroboration"] = {
            "verdict":   verdict,
            "s2_hits":   s2_hits,
            "s3_hits":   s3_hits,
            "s2_other":  [],
            "s3_other":  s3_other,
            "s2_source": s2_source,   # 'loop' | 'process' | None
            "note":      (f"S2={'+' if s2_ok else '-'}"
                          f"{('(' + s2_source + ')') if s2_source else ''} "
                          f"S3={'+' if s3_ok else '-'} "
                          f"families={families!r}"),
        }
        verdict_counts[verdict] += 1

    return {
        "verdict_counts":      verdict_counts,
        "downgrades":          downgrades,
        "unlabelled_evidence": unlabelled_evidence,
    }
