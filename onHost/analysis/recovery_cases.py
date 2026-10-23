"""Recovery-Case (RC) taxonomy mapped onto the new PinTool feed.

Each case is a **conjunction** of evidence primitives — all must return
True or the case does not fire.  Confidence values come from the source
literature, not from internal scoring.

Three primitive classes:

  * **OK**         — implementable with no extra PinTool work.
  * **DEGRADED**   — implementable with a weakened proxy; fires less
                     often than the legacy primitive would have.
  * **UNAVAILABLE**— requires a field the new PinTool does not emit
                     (e.g. raw key bytes).  Always returns False with a
                     descriptive note.  Any case that depends on at
                     least one UNAVAILABLE primitive cannot fire today.
"""
from __future__ import annotations

import os
from typing import Callable


# ---------------------------------------------------------------------------
# Context shape (built by `evaluate()` below)
# ---------------------------------------------------------------------------
# {
#     "bundle":         bundle dict from loaders.load_bundle
#     "loop_labels":    {loop_id: classifier_output}
#     "io_summary":     io_summary.summarize(...)
#     "crypto_summary": crypto_summary.summarize(...)
#     "trace_dir":      absolute path
# }
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Primitive: API event presence
# ---------------------------------------------------------------------------
def _api_set(ctx: dict) -> set[str]:
    api = set((ctx.get("crypto_summary") or {}).get("by_api", {}).keys())
    api |= set((ctx.get("io_summary") or {}).get("by_api", {}).keys())
    return api


def has_event(api: str) -> Callable:
    def check(ctx: dict) -> tuple[bool, str, str]:
        hits = _api_set(ctx) & {api}
        n = (ctx.get("crypto_summary", {}).get("by_api") or {}).get(api, 0) \
            + (ctx.get("io_summary", {}).get("by_api") or {}).get(api, 0)
        return (bool(hits), f"{api} calls: {n}", "OK")
    return check


def has_any_event(apis) -> Callable:
    apis = tuple(apis)
    def check(ctx: dict) -> tuple[bool, str, str]:
        seen = _api_set(ctx) & set(apis)
        return (bool(seen),
                f"hit: {sorted(seen) or 'none'}",
                "OK")
    return check





# ---------------------------------------------------------------------------
# Primitive: loaded module / file
# ---------------------------------------------------------------------------
def file_present(rel_path: str) -> Callable:
    """Equivalence mapping (paper §III-C verbatim: "key_residue_map.json present"
    means "key residue evidence exists for this trace"):
      - key_residue_map.json
          present if any `key_residue_snapshots_<N>.jsonl` chunk exists OR
          any crypto_<N>.bin snapshot file exists OR any byte-signature
          scanner returned a hit (paper §III).
      - decryption_essentials.json
          present if any `crypto_events_<N>.jsonl` chunk carries an event
          with kind ∈ {keygen, key_import, key_export, kdf}.
    """
    # walk subdirs so chunk files emitted to trace_dir/crypto/
    # or trace_dir/residue/ by some PinTool configs are still detected. The
    # original os.listdir(td) only saw immediate children and silently missed
    # equivalence evidence. Aligned with pagefile_or_hiberfile_present which
    # already uses os.walk with an early break.
    def _has_chunked(td: str, base: str) -> bool:
        try:
            for _r, _, files in os.walk(td):
                for name in files:
                    if name.startswith(base + "_") and name.endswith(".jsonl"):
                        return True
        except OSError:
            return False
        return False

    # same subdir-blindness applied here.
    def _has_crypto_bin(td: str) -> bool:
        try:
            for _r, _, files in os.walk(td):
                for name in files:
                    if name.startswith("crypto_") and name.endswith(".bin"):
                        return True
        except OSError:
            return False
        return False

    def _has_byte_sig_hit(ctx: dict) -> tuple[bool, str]:
        bs = ctx.get("byte_sigs") or {}
        for k in ("aeskeyfind_count", "wanakiwi_prime_count",
                   "bcrypt_rsa_blob_count", "cryptoapi_rsa_blob_count",
                   "avaddon_session_count"):
            n = int(bs.get(k) or 0)
            if n > 0:
                return (True, f"{k}={n}")
        return (False, "")

    def _has_essentials_kind(ctx: dict) -> tuple[bool, str]:
        evs = (ctx.get("bundle") or {}).get("crypto_events") or []
        wanted = {"keygen", "key_import", "key_export", "kdf"}
        kinds_seen: set[str] = set()
        for ev in evs:
            k = ev.get("kind")
            if k in wanted:
                kinds_seen.add(k)
        if kinds_seen:
            return (True, "kinds=" + ",".join(sorted(kinds_seen)))
        return (False, "")

    def check(ctx: dict) -> tuple[bool, str, str]:
        td = ctx["trace_dir"]
        # Literal file: present?
        p = os.path.join(td, rel_path)
        if os.path.isfile(p):
            return (True, f"{rel_path}: present", "OK")
        # Equivalences.
        if rel_path == "key_residue_map.json":
            if _has_chunked(td, "key_residue_snapshots"):
                return (True,
                        f"{rel_path}: present via chunked "
                        f"key_residue_snapshots_N.jsonl", "OK")
            if _has_crypto_bin(td):
                return (True,
                        f"{rel_path}: present via crypto_N.bin snapshot files",
                        "OK")
            ok, why = _has_byte_sig_hit(ctx)
            if ok:
                return (True,
                        f"{rel_path}: present via byte-signature hit ({why})",
                        "OK")
        elif rel_path == "decryption_essentials.json":
            if _has_chunked(td, "crypto_events"):
                ok, why = _has_essentials_kind(ctx)
                if ok:
                    return (True,
                            f"{rel_path}: present via crypto_events_N.jsonl ({why})",
                            "OK")
        return (False, f"{rel_path}: absent", "OK")
    return check


def pagefile_or_hiberfile_present() -> Callable:
    NAMES = ("pagefile.sys", "hiberfil.sys", "swapfile.sys")
    name_set = set(NAMES)
    def check(ctx: dict) -> tuple[bool, str, str]:
        # original code did one os.walk per NAME (3·N traversal).
        # Now do a single walk and use a set intersection; bail out as soon
        # as all three names have been observed. For traces with deep
        # directory trees this turns minutes into seconds.
        root = ctx["trace_dir"]
        present: set[str] = set()
        for _r, _, files in os.walk(root):
            hits = name_set & set(files)
            if hits:
                present |= hits
                if len(present) == len(name_set):
                    break
        present_list = sorted(present)
        return (bool(present_list),
                f"forensic files: {present_list or 'none'}", "OK")
    return check


# ---------------------------------------------------------------------------
# Primitives that the new PinTool cannot answer
# ---------------------------------------------------------------------------
def _unavailable(why: str) -> Callable:
    def check(ctx: dict) -> tuple[bool, str, str]:
        return (False, f"unavailable in new PinTool feed: {why}", "UNAVAILABLE")
    return check


# asym_blob_complete / asym_blob_format_in / asym_blob_is_private_not_public
# were removed: the PinTool emits in_buf/out_buf as POINTERS (HexAddr), never
# an out_buf_hex content field, so crypto_summary.asym_blobs is always empty
# and these primitives could never fire. RC-01 is now snapshot-byte-signature
# based (see its evidence_required), and RC-03's modulus comes from
# _moduli_from_snapshot_blobs in byte_signature_scanner.


def sym_keys_unique_at_least(n: int) -> Callable:
    def check(ctx: dict) -> tuple[bool, str, str]:
        cs = ctx.get("crypto_summary") or {}
        cnt = cs.get("sym_keys_count") or 0
        return (cnt >= n, f"{cnt} unique sym keys; threshold {n}", "OK")
    return check


def captured_symmetric_keys_at_least(n: int) -> Callable:
    """RC-07 (PayBreak) accepts captured symmetric session keys from EITHER the
    standard sym_keys inventory (keygen/kdf/key_import path) OR the wrapped-key
    inventory — keys captured plaintext at an RSA-wrap input (e.g. Chaos's per-file
    "KEY|IV"). The wrapped keys are kept OUT of `sym_keys_count` so they do not feed
    RC-04/RC-05 (which require a key produced by the hooked keygen/RNG path); only
    RC-07 reads them here."""
    def check(ctx: dict) -> tuple[bool, str, str]:
        cs = ctx.get("crypto_summary") or {}
        sym = int(cs.get("sym_keys_count") or 0)
        wrapped = int(cs.get("wrapped_session_keys_count") or 0)
        cnt = max(sym, wrapped)
        src = "sym_keys" if sym >= wrapped else "wrapped-key sink_plaintext"
        return (cnt >= n, f"{cnt} captured sym keys ({src}); threshold {n}", "OK")
    return check


def sym_key_with_specific_algorithm(algorithm: str) -> Callable:
    """Algorithm tag is best-effort: inferred from the API the key came
    out of (e.g. AES_set_encrypt_key -> AES)."""
    def check(ctx: dict) -> tuple[bool, str, str]:
        cs = ctx.get("crypto_summary") or {}
        algo = algorithm.lower()
        for k in cs.get("sym_keys") or []:
            api = (k.get("api") or "").lower()
            if algo in api:
                return (True, f"key from {k.get('api')} ({k.get('len')}B)",
                        "DEGRADED")
        return (False, f"no key tied to algorithm={algorithm}", "DEGRADED")
    return check


def residue_class_at_least(level: str,
                            allowed_byte_sigs: list | None = None) -> Callable:
    """Memory residue tier from `residue_scanner.scan()` (paper §III).

    added `allowed_byte_sigs` filter. When the residue
    class was promoted by `byte_sig_promotion` but the promoting signature
    is not in the RC-appropriate allowlist, the residue is treated as NOT
    qualifying for this RC, even if the headline class meets `level`.

    Rationale: `aeskeyfind` legitimately promotes residue for AES-related
    RCs (RC-04, RC-06), but should NOT promote residue for RSA-keypair
    RCs (RC-02, RC-03) — AES round-key schedules are not RSA keypairs.
    Without this filter every trace that ever loads any AES code is a
    false positive on RC-02 / RC-03.

    `allowed_byte_sigs` is a list of substrings; a promotion reason like
    "aeskeyfind:3" qualifies iff at least one allowed substring is a
    prefix of it. Pass `None` (default) to accept any promotion (legacy).
    """
    order = {"NONE": 0, "LOW": 1, "MID": 2, "HIGH": 3}
    threshold = order.get(level.upper(), 0)
    allow = tuple(str(s).lower() for s in (allowed_byte_sigs or ()))

    def check(ctx: dict) -> tuple[bool, str, str]:
        res = ctx.get("residue") or {}
        cls = (res.get("residue_class") or "NONE").upper()
        n = res.get("total_matches", 0)
        u = res.get("unique_tags_with_hit", 0)
        scanned = res.get("snapshots_scanned", 0)

        ok = order.get(cls, 0) >= threshold

        # when class came from a byte-sig promotion (not from real
        # match hits), restrict to RC-appropriate signatures.
        promo = res.get("byte_sig_promotion") or {}
        promo_from = (promo.get("from") or "").upper()
        promo_to = (promo.get("to") or "").upper()
        was_promoted = (promo_from and promo_to and promo_from != promo_to
                        and n == 0 and u == 0)

        if ok and was_promoted and allow:
            reasons = promo.get("reasons") or []
            matched_allow = [
                r for r in reasons
                if any(r.lower().startswith(a) for a in allow)
            ]
            if not matched_allow:
                # The residue HIGH/MID came ONLY from a byte signature that is
                # not recovery-relevant for THIS case -- e.g. an AES key
                # (aeskeyfind / avaddon) cannot stand in for the RSA-keypair
                # residue that RC-02 / RC-03 require. Letting it pass would
                # over-claim an RSA private key from an AES hit, so we revert
                # to the un-promoted class: the rule then fails unless the raw
                # (literal-match) residue alone already met the threshold.
                raw = (promo_from or "NONE").upper()
                ok_raw = order.get(raw, 0) >= threshold
                return (
                    ok_raw,
                    f"residue={cls} promoted via {reasons!r}, but none match "
                    f"this RC's signatures {list(allow)}; reverting to "
                    f"un-promoted class {raw} -> "
                    f"{'pass' if ok_raw else 'fail'}; threshold={level}",
                    "OK",
                )

        if scanned == 0:
            return (ok, f"residue={cls} (no snapshots scanned); threshold={level}",
                    "OK")
        return (ok,
                f"residue={cls} ({n} matches, {u} unique tags, "
                f"{scanned} snapshots scanned); threshold={level}",
                "OK")
    return check


def hardcoded_key_ratio_at_least(ratio: float) -> Callable:
    """Implemented via the chain graph (chain.py).

    The ratio is ``sinks_without_rng_ancestor / sink_count``. A high
    ratio means most encryption sinks were fed by an embedded-root tag
    (no observable RNG seed in the same trace), which is the signature
    of a hardcoded symmetric key embedded in .rdata or computed at
    process start without entropy mixing.
    """
    def check(ctx: dict) -> tuple[bool, str, str]:
        chain = ctx.get("chain") or {}
        stats = chain.get("stats") or {}
        sink_count = int(stats.get("sink_count") or 0)
        if sink_count == 0:
            return (False, "no crypto sinks observed in chain graph", "OK")
        without = int(stats.get("sinks_without_rng_ancestor") or 0)
        observed = without / sink_count
        return (observed >= ratio,
                f"{without}/{sink_count}={observed:.2f}; threshold={ratio:.2f}",
                "OK")
    return check


def weak_rng_with_keygen() -> Callable:
    """RC-05 evidence: an RNG source whose downstream actually reaches a
    keygen-kind derivation.  The chain graph already records
    rng→keygen reachability; here we just confirm at least one path
    exists.  The PinTool hooks `rand`/`srand` are out of scope for the
    new feed, but any cryptographic-API RNG (BCryptGenRandom,
    RAND_bytes, …) feeding a key derivation IS what RC-05 fires on in
    practice — Bart, Petya v1, BadBlock all routed weak entropy through
    a key-schedule call captured in this graph.
    """
    def check(ctx: dict) -> tuple[bool, str, str]:
        chain = ctx.get("chain") or {}
        paths = chain.get("rng_to_keygen_paths") or []
        if not paths:
            return (False,
                    "no rng→keygen path in chain graph",
                    "DEGRADED")
        sample = paths[0]
        return (True,
                f"{len(paths)} rng→keygen path(s); e.g. tag "
                f"{sample['rng_tag']}→{sample['keygen_tag']} via "
                f"{sample.get('keygen_apis')}",
                "DEGRADED")
    return check





# ---------------------------------------------------------------------------
# Byte-signature wrapper primitives (aes_key_schedule_in_residue /
# bcrypt_rsa_blob_in_residue / avaddon_session_key_in_residue) were removed:
# no RC referenced them. The byte-signature scanners feed residue_class_at_least
# directly via residue_scanner promotion; the raw counts live in
# byte_signature_scanner's aggregate.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# CryptGenKey CRYPT_EXPORTABLE flag probe (auxiliary; not a recovery gate).
# CRYPT_EXPORTABLE governs CryptExportKey; this probe is informational only
# and is not referenced by any shipped CASE's evidence_required.
# ---------------------------------------------------------------------------
def cryptgenkey_exportable_flag_set() -> Callable:
    def check(ctx: dict) -> tuple[bool, str, str]:
        events = (ctx.get("bundle") or {}).get("crypto_events") or []
        hits = 0
        for ev in events:
            api = (ev.get("api") or "").lower()
            if api not in ("cryptgenkey", "cryptderivekey"):
                continue
            # Args are usually emitted as hex strings; CRYPT_EXPORTABLE
            # is bit 0 of dwFlags.
            for argk in ("a3", "a4", "a5", "flags", "dwFlags"):
                v = ev.get(argk)
                if v is None:
                    continue
                try:
                    vi = int(str(v), 16) if isinstance(v, str) else int(v)
                    if vi & 0x00000001:
                        hits += 1
                        break
                except (ValueError, TypeError):
                    continue
        return (hits > 0,
                f"CryptGenKey calls with CRYPT_EXPORTABLE bit set: {hits}",
                "DEGRADED")
    return check


# ---------------------------------------------------------------------------
# NO_RUNTIME_KEYGEN, embedded-root proxy
# (wanakiwi_prime_in_residue wrapper removed: RC-03 uses residue_class_at_least
# over the wanakiwi_prime byte-signature, whose modulus comes from
# _moduli_from_snapshot_blobs in byte_signature_scanner.)
# ---------------------------------------------------------------------------


def no_runtime_keygen(max_rng_calls: int = 0) -> Callable:
    """RC-04 negative-evidence primitive (Bajpai 2020 Strategy C).
    Hardcoded-key samples should not be calling RNG/keygen APIs at all
    before they encrypt -- they read the key from .rdata directly.
    Returns True when total RNG calls observed is <= max_rng_calls."""
    rng_apis = ("BCryptGenRandom", "SystemFunction036", "ProcessPrng",
                 "CryptGenRandom", "RtlGenRandom")
    # Must match chain.py _KEYGEN_APIS exactly, so RC-04's hardcoded_key_recoverable
    # Strategy-C fallback (which requires "no runtime keygen") does not false-pass on
    # a sample that generates keys via Finalize/Derive/CryptDerive.
    keygen_apis = ("BCryptGenerateSymmetricKey", "BCryptGenerateKeyPair",
                    "BCryptFinalizeKeyPair", "BCryptDeriveKey",
                    "CryptGenKey", "CryptDeriveKey")
    def check(ctx: dict) -> tuple[bool, str, str]:
        by_api = (ctx.get("crypto_summary") or {}).get("by_api") or {}
        rng_total = sum(by_api.get(a, 0) for a in rng_apis)
        kg_total  = sum(by_api.get(a, 0) for a in keygen_apis)
        if rng_total > max_rng_calls or kg_total > 0:
            return (False,
                    f"RNG calls={rng_total}, keygen calls={kg_total} "
                    f"(both must be 0 for hardcoded-key indicator)",
                    "OK")
        return (True,
                f"no runtime RNG ({rng_total}) and no keygen ({kg_total}) "
                f"-- consistent with hardcoded-key model",
                "OK")
    return check


def embedded_root_count_at_least(n: int = 1) -> Callable:
    """Chain-graph proxy for "key bytes present in process without an
    observable RNG ancestor". Drives RC-04 when sym_keys_unique is 0
    (PinTool did not dump buffer hex) -- the embedded_root count is the
    next-best published evidence (Bajpai 2020 Strategy C)."""
    def check(ctx: dict) -> tuple[bool, str, str]:
        chain = ctx.get("chain") or {}
        stats = chain.get("stats") or {}
        cnt = int(stats.get("embedded_root_count") or 0)
        return (cnt >= n,
                f"chain embedded_root_count={cnt}; threshold={n}",
                "OK")
    return check


def hardcoded_key_recoverable(min_sym: int = 1, min_embedded: int = 1) -> Callable:
    """RC-04 recoverability gate (Bajpai & Enbody 2020, Strategy C).

    A hardcoded symmetric key is recoverable when EITHER:
      (a) >= min_sym captured symmetric key(s) are present (direct evidence --
          the PinTool dumped or the sample imported the key), OR
      (b) >= min_embedded embedded-root key node(s) exist AND the process makes
          NO runtime RNG/keygen call. This is Bajpai Strategy C negative
          evidence: an inline-crypto locker reads its key from .rdata and never
          calls a key-import/keygen API, so sym_keys is 0 -- yet an embedded
          constant feeding encryption with zero RNG/keygen IS the static key.

    Branch (b) lets RC-04 fire on inline-crypto hardcoded-key lockers
    (sym_keys == 0) WITHOUT over-claiming: the no-RNG/no-keygen gate rules out
    any per-victim derivation, so the only remaining key source is the embedded
    constant. Composed from the existing sym_keys_unique_at_least /
    embedded_root_count_at_least / no_runtime_keygen primitives so the field
    reads stay identical to those already-validated checks.
    """
    _sym  = sym_keys_unique_at_least(min_sym)
    _emb  = embedded_root_count_at_least(min_embedded)
    _nokg = no_runtime_keygen(0)

    def check(ctx: dict) -> tuple[bool, str, str]:
        ok_sym, obs_sym, sup_sym = _sym(ctx)
        if ok_sym:
            return (True, f"direct captured key: {obs_sym}", sup_sym)
        ok_emb, obs_emb, _ = _emb(ctx)
        ok_kg,  obs_kg,  _ = _nokg(ctx)
        if ok_emb and ok_kg:
            return (True,
                    f"Bajpai Strategy C static-key fallback: {obs_emb}; "
                    f"{obs_kg}",
                    "OK")
        return (False,
                f"no captured sym key and no static-key fallback "
                f"({obs_sym}; {obs_emb}; {obs_kg})",
                sup_sym)
    return check


def decisive_cipher_artifact() -> Callable:
    """RC-06 trigger: a DECISIVE cryptographic artifact was captured in the
    trace -- a concrete, identifying *value*, not a vague pattern or API call.

    Fires when at least one of:
      A. a cipher magic constant hit in a loop immediate whose catalog
         `recovery_role` marks it recoverable -- sym_cipher (aes_sbox,
         chacha20, tea_delta, ...), asym_privkey (RSA/ECC private-key blob
         magics), or family_marker (wanacry, lockbit3, babuk, ...). Roles that
         carry no recoverable file key -- hash, mac, kdf, asym_padding,
         asym_pubkey, asym_curve_const, format, algo_id -- are excluded by
         RULE (the catalog field), not by any keyword heuristic. An
         `ambiguous` constant (e.g. tea_delta, shared by TEA/XTEA/Serpent/RC5)
         still qualifies but is tagged "~" / needs-disambiguation: it pins a
         cipher *family*, and the exact member is resolvable by further
         recovery-case analysis (round pattern, key length, neighbours).
      B. a heap-snapshot byte signature hit (aeskeyfind / bcrypt_rsa_blob /
         cryptoapi_rsa_blob / avaddon_session / wanakiwi_prime) -- an actual key
         residue value.

    A `pattern_only` loop label (a cipher-shaped round structure with NO
    backing constant or residue, e.g. inline-AES S-box without an immediate)
    does NOT qualify -- only a captured *value* counts.
    """
    # RC-06 includes a constant iff its catalog recovery_role is recoverable.
    RECOVERABLE_ROLES = {"sym_cipher", "asym_privkey", "family_marker"}
    BYTE_SIGS = ("aeskeyfind", "bcrypt_rsa_blob", "cryptoapi_rsa_blob",
                 "avaddon_session", "wanakiwi_prime")

    def check(ctx: dict) -> tuple[bool, str, str]:
        artifacts: list[str] = []
        loop_labels = ctx.get("loop_labels") or {}
        # A. recovery-relevant cipher magic constant in a loop immediate.
        #    The base filter is purely the catalog `recovery_role` field (a
        #    rule, not a heuristic). An *ambiguous* constant (e.g. golden-ratio
        #    0x9E3779B9, shared by TEA/XTEA/Serpent/RC5/RC6 AND generic
        #    hashing/PRNG) is additionally gated on cross_axis: it counts only
        #    when its loop's verdict is corroborated/byte_gated -- i.e. the
        #    constant agrees with a co-occurring cipher *round pattern* in that
        #    same loop. A lone golden-ratio in a hashing loop is
        #    pattern_only/downgraded and is excluded (kills the disambiguation
        #    false positives without a keyword heuristic).
        cc = ctx.get("cipher_constants") or {}
        for h in cc.get("hits") or []:
            if h.get("recovery_role") not in RECOVERABLE_ROLES:
                continue
            if h.get("catalog_ambiguous"):
                # An ambiguous constant -- a word shared by several ciphers,
                # e.g. golden-ratio 0x9E3779B9 (TEA/XTEA/Serpent/RC5/RC6) -- is
                # accepted only when the catalog names a `disambiguating_round`
                # AND the SAME loop was originally classified as exactly that
                # round pattern. Pure rule: catalog field == loop's pre-
                # downgrade label. (cross_axis downgrades a multi-cipher loop's
                # label to unknown.utility, so the real classification is read
                # from corroboration.original_label.) No substring/keyword.
                target = h.get("disambiguating_round")
                if not target:
                    continue
                lid = h.get("loop_id")
                lab = (loop_labels.get(lid)
                       or loop_labels.get(str(lid)) or {})
                corr = lab.get("corroboration") or {}
                orig = corr.get("original_label") or lab.get("label") or ""
                if orig != target:
                    continue
            tag = "~" if h.get("catalog_ambiguous") else ""
            artifacts.append(
                f"const{tag}:{h.get('constant_name')}/{h.get('algo')}"
                f"@loop{h.get('loop_id')}")
        # B. heap byte signature (an actual key-residue value)
        bs = ctx.get("byte_sigs") or {}
        for sig in BYTE_SIGS:
            n = int(bs.get(f"{sig}_count", 0) or 0)
            if n:
                artifacts.append(f"bytesig:{sig}({n})")
        uniq = list(dict.fromkeys(artifacts))
        amb = any(a.startswith("const~") for a in uniq)
        note = " (incl. ambiguous; needs disambiguation)" if amb else ""
        return (bool(uniq),
                f"decisive artifacts={len(uniq)}{note}: {uniq[:4] or 'none'}",
                "OK")
    return check


# ---------------------------------------------------------------------------
# Primitive registry
# ---------------------------------------------------------------------------
# NOTE: has_event, sym_key_with_specific_algorithm, and
# cryptgenkey_exportable_flag_set are registered for external / auxiliary
# callers; they are not referenced by any shipped CASE's evidence_required.
PRIMITIVE_FACTORY: dict[str, Callable] = {
    "has_event":                        has_event,
    "has_any_event":                    has_any_event,
    "sym_keys_unique_at_least":         sym_keys_unique_at_least,
    "captured_symmetric_keys_at_least": captured_symmetric_keys_at_least,
    "sym_key_with_specific_algorithm":  sym_key_with_specific_algorithm,
    "residue_class_at_least":           residue_class_at_least,
    "hardcoded_key_ratio_at_least":     hardcoded_key_ratio_at_least,
    "hardcoded_key_recoverable":        hardcoded_key_recoverable,
    "weak_rng_with_keygen":             weak_rng_with_keygen,
    "file_present":                     file_present,
    "decisive_cipher_artifact":         decisive_cipher_artifact,
    "cryptgenkey_exportable_flag_set":  cryptgenkey_exportable_flag_set,
}


# ---------------------------------------------------------------------------
# Case registry — the recovery-case (RC) definitions.
# Only `evidence_required` (spec) is used by the engine here; the rest
# is metadata carried into the report.
# ---------------------------------------------------------------------------
CASES = [
    {
        "case_id": "RC-01",
        "name":    "rsa_private_blob_exported_full",
        "strategy": "asym_priv_universal",
        "confidence_when_met": 0.98,
        "real_samples": ["AKO/MedusaLocker (export-to-disk variant)"],
        "description":
            "CryptExportKey / BCryptExportKey returned a full PRIVATEKEYBLOB. "
            "Self-describing blob -> deterministic decryption. NB: this "
            "case fires only when the export actually happened in-trace; "
            "see RC-03 for WannaCry's prime-scan path and RC-06 for "
            "Avaddon's AES session-key heap residue.",
        "evidence_required": [
            # Snapshot-based detection. The PinTool emits in_buf/out_buf as
            # POINTERS (HexAddr), not out_buf_hex content, so
            # crypto_summary.asym_blobs is always empty and the old
            # asym_blob_complete/is_private/format_in primitives can never fire.
            # The exported full PRIVATEKEYBLOB is instead captured in the
            # key-birth dump (crypto_N.bin) and detected by the RSA-private
            # byte signatures. RC-01 = an export/finalize event ∧ a complete
            # RSA private blob present in the dump. (RC-02 is the same residue
            # WITHOUT requiring the export event, hence RC-01's higher
            # confidence: the export proves the full self-describing blob left
            # the CSP.)
            {"primitive": "has_any_event",
              "kwargs": {"apis": ["BCryptExportKey", "CryptExportKey",
                                    "BCryptFinalizeKeyPair"]}},
            {"primitive": "residue_class_at_least",
              "kwargs": {"level": "HIGH",
                          "allowed_byte_sigs": ["bcrypt_rsa_blob",
                                                  "cryptoapi_rsa_blob"]}},
        ],
    },
    {
        "case_id": "RC-02", "name": "per_run_rsa_keypair_in_heap",
        "strategy": "memory_residue_scan", "confidence_when_met": 0.85,
        "real_samples": ["early CryptoLocker (server-keygen variants)",
                          "TorrentLocker"],
        "description":
            "Ransomware generates RSA keypair at runtime; destroy path missed -> "
            "private exponent remains in heap.",
        "evidence_required": [
            # Recovery-FEASIBILITY signal (not a recovery guarantee): a private
            # RSA key blob sitting in a key-birth dump is directly recoverable
            # by follow-up analysis, so the dump-key residue alone qualifies.
            #   * cryptoapi_rsa_blob covers legacy CryptoAPI PRIVATEKEYBLOBs whose
            #     magic sits after an 8-byte BLOBHEADER -- the BCRYPT-anchored
            #     scan structurally cannot see them.
            #   * The keygen event (paper §III-C original conjunct) is demoted
            #     from a hard gate to metadata: an *imported* attacker keypair
            #     left in heap is just as recoverable as a runtime-generated
            #     one, so requiring keygen would wrongly drop those.
            # residue ≥ HIGH is reached only via an RSA-private byte signature
            # (bcrypt/cryptoapi/wanakiwi), so this still demands an actual key in
            # the dump -- it is not loosened to "RSA was merely used".
            {"primitive": "residue_class_at_least",
              "kwargs": {"level": "HIGH",
                          "allowed_byte_sigs": ["bcrypt_rsa_blob",
                                                  "cryptoapi_rsa_blob",
                                                  "wanakiwi_prime"]}},
            {"primitive": "file_present",
              "kwargs": {"rel_path": "key_residue_map.json"}},
        ],
    },
    {
        "case_id": "RC-03", "name": "memory_residue_prime_scan_cryptoapi",
        "strategy": "memory_residue_scan", "confidence_when_met": 0.55,
        # Source: Guinet (wannakey, 2017) + Delpy/Suiche (wanakiwi, 2017).
        # NB: the gating test is **divisibility** against the known public
        # modulus N (extracted from 00000000.pky), NOT Miller-Rabin primality.
        # Miller-Rabin (25 rounds) appears only as an internal sanity check
        # inside wannakey's bigint module. The actual algorithm: 128-byte
        # window slid at 4-byte stride over MEM_PRIVATE | PAGE_READWRITE
        # regions, Shannon entropy >= 0.5 (wanakiwi) or >= 0.7 (wannakey),
        # accept candidate iff N % candidate == 0.
        # OS gate: XP / 2003 / Vista / 7 / 2008 / 2008R2. Win10+ patched
        # CryptReleaseContext to zeroize -> technique fails.
        "real_samples": ["WannaCry (XP/Win7, via wanakiwi/wannakey)"],
        "description":
            "wanakiwi/wannakey technique: CryptoAPI heap retains 128-byte RSA "
            "primes p, q after CryptReleaseContext on pre-Win10 systems. "
            "Found by sliding 128-byte window at 4-byte stride; accepted "
            "via N % candidate == 0 divisibility against on-disk public "
            "modulus.",
        "evidence_required": [
            # Paper §III-C Table 1 verbatim conjunction:
            #   CryptGenKey or CryptAcquireContext event ∧
            #   residue ≥ MID ∧ key_residue_map.json present
            {"primitive": "has_any_event",
              "kwargs": {"apis": ["CryptGenKey", "CryptAcquireContextW",
                                    "CryptAcquireContextA"]}},
            # RC-03 is wanakiwi/wannakey RSA-prime scan;
            # only wanakiwi_prime byte signature may legitimately promote residue.
            {"primitive": "residue_class_at_least",
              "kwargs": {"level": "MID",
                          "allowed_byte_sigs": ["wanakiwi_prime"]}},
            {"primitive": "file_present",
              "kwargs": {"rel_path": "key_residue_map.json"}},
        ],
    },
    {
        "case_id": "RC-04", "name": "untraced_symmetric_key_root",
        "strategy": "untraced_root_replay", "confidence_when_met": 0.95,
        # Source: Bajpai & Enbody 2020 (IEEE Cyber Security 9138878),
        # "Strategy C - Static symmetric key".
        # Paper §III-C lists the canonical embedded-key exemplars for RC-04
        # (Jigsaw, DirCrypt, AIDS Trojan) from the literature; HDLocker is
        # this work's evaluated instance of the untraced-root branch.
        "real_samples": ["JigSaw (.NET, 16-byte AES hardcoded in string table)",
                          "DirCrypt",
                          "Locky static fallback path",
                          "AIDS Trojan (1989)"],
        "description":
            "A symmetric-encryption sink whose observed key-flow path has no "
            "RNG/keygen ancestor (sinks-without-RNG-ancestor ratio >= 0.8). "
            "The root may be build-fixed (embedded in .rdata/.data) OR a "
            "derivation below the capture boundary; RC-04 flags the untraced "
            "root as a lead, and the key origin requires analyst verification "
            "(replay the captured/root key, then confirm whether it is "
            "build-fixed).",
        "evidence_required": [
            # Paper §III-C Table 1 conjunction, with the Bajpai Strategy C
            # negative-evidence fallback:
            #   hardcoded_key_ratio >= 0.8
            #   AND ( sym_keys >= 1  OR  (embedded_root >= 1 AND no RNG/keygen) )
            #   AND sym-encrypt event
            # The OR lets inline-crypto hardcoded-key lockers -- which never
            # call a key-import API, so sym_keys == 0 -- fire via the
            # embedded-root + no-keygen Strategy C path, without over-claiming
            # (ratio >= 0.8 stays the dominant gate; the fallback additionally
            # requires zero runtime RNG/keygen).
            {"primitive": "hardcoded_key_ratio_at_least",
              "kwargs": {"ratio": 0.8}},
            {"primitive": "hardcoded_key_recoverable",
              "kwargs": {"min_sym": 1, "min_embedded": 1}},
            {"primitive": "has_any_event",
              "kwargs": {"apis": ["BCryptEncrypt", "BCryptDecrypt",
                                    "CryptEncrypt", "CryptDecrypt",
                                    "EVP_EncryptUpdate", "EVP_DecryptUpdate",
                                    "AES_encrypt", "AES_decrypt",
                                    "RC4", "mbedtls_aes_crypt_cbc",
                                    "mbedtls_aes_crypt_ecb"]}},
        ],
    },
    {
        "case_id": "RC-05", "name": "weak_predictable_rng_seed",
        "strategy": "rng_seed_replay", "confidence_when_met": 0.70,
        # Source: AVG/Avast Bart writeup (2016/2017) + Hasherezade Petya v1
        # decoder (2016) + Check Point Research (2016). NB: the actual
        # weaknesses are NOT srand(GetTickCount()):
        #   Bart   = PKZIP traditional cipher (PKWARE stream cipher) +
        #            Biham-Kocher known-plaintext attack via PkCrack.
        #            Trigger: .bart.zip extension + ZIP local header
        #            PK\\x03\\x04 + general-purpose flag bit 0 + plaintext
        #            pair available.
        #   Petya v1 = s20_littleendian function returns 16-bit instead of
        #            32-bit, collapsing 16-byte Salsa20 key to 8 effective
        #            bytes (pattern cc??cc??cc??cc??). Genetic-algorithm
        #            crack ~seconds-to-minutes using the 0x37-filled
        #            verification buffer at sector 0x6e21.
        "real_samples": ["Bart (PKZIP+PkCrack)",
                          "Petya v1 \"Red Petya\" (s20_littleendian bug)"],
        "description":
            "Implementation-flaw recovery: either a weak cipher mode "
            "(PKZIP/PKWARE) crackable via known-plaintext attack, or a "
            "truncated PRNG/stream-cipher state crackable via brute-force "
            "anchored on a known verification buffer.",
        "evidence_required": [
            # Paper §III-C Table 1 verbatim:
            #   Weak-RNG-into-keygen path ∧ unique sym keys ≥ 1
            {"primitive": "weak_rng_with_keygen", "kwargs": {}},
            {"primitive": "sym_keys_unique_at_least", "kwargs": {"n": 1}},
        ],
    },
    {
        "case_id": "RC-06", "name": "decisive_cipher_artifact_captured",
        "strategy": "concrete_artifact_to_cipher_id", "confidence_when_met": 0.65,
        "real_samples": ["HDLocker (TEA-16 delta constant captured in a loop "
                         "immediate; binary-embedded keyspace bruteforce, own "
                         "paper §IV-B)"],
        "description":
            "A decisive cryptographic artifact -- a non-ambiguous cipher magic "
            "constant, a heap key-residue byte signature, or an ambiguous "
            "constant that an in-loop round pattern corroborates -- was "
            "captured in the trace. Unlike a vague AES/XOR library-API presence "
            "(which carries no recoverable value), or a pattern-only round "
            "structure with no backing constant, this concrete artifact pins "
            "the cipher/family and opens a partial-recovery path even when the "
            "full key is not dumped.",
        "evidence_required": [
            # A concrete, identifying artifact is present: a non-ambiguous
            # cipher magic constant (A) ∨ a key-residue byte signature (B) ∨
            # an ambiguous constant corroborated by its in-loop round pattern
            # (A's ambiguous branch). A pattern-only round structure with no
            # backing constant, and vague library-API presence, are excluded.
            {"primitive": "decisive_cipher_artifact", "kwargs": {}},
        ],
    },
    {
        "case_id": "RC-07", "name": "captured_symmetric_session_keys",
        "strategy": "sym_brute_correlation", "confidence_when_met": 0.95,
        # Source: Kolodenker et al. (PayBreak, AsiaCCS 2017). PayBreak hooks
        # 17 APIs (12 CryptoAPI + 1 CNG/BCryptEncrypt + 4 file I/O) via
        # Microsoft Detours, forces CRYPT_EXPORTABLE on every key handle,
        # exports plaintext key + IV + alg_id at each CryptEncrypt call,
        # RSA-encrypts under user pubkey, appends to vault at
        # C:\\CryptoHookLog.dll.
        # NB: ShieldFS (Continella et al., ACSAC 2016) is NOT a per-file
        # session-key recovery -- it is a copy-on-write filesystem that
        # preserves pre-modification pages; the memory key-schedule scan
        # in ShieldFS is an IOC feature only, not used for decryption.
        "real_samples": ["12 of 20 active families in PayBreak Table 1: "
                          "Almalocker, Cerber, Chimera, CryptoFortress, "
                          "CryptoLocker, CryptoWall, CrypWall, GPcode, "
                          "Locky, SamSam, Thor Locky, Tox"],
        "description":
            "A captured symmetric session key is present together with a "
            "decryption-essentials artifact, indicating a PayBreak-style "
            "key-escrow hook. Recovery: replay the captured (key, IV, alg) "
            "material against the encrypted files. NOTE: the evidence proves "
            "a captured symmetric key + an essentials file -- it does NOT by "
            "itself prove that every file's session key was escrowed before "
            "destroy (that is the PayBreak mechanism this case emulates, not "
            "what the trace verified).",
        "evidence_required": [
            # Paper §III-C Table 1 abbreviated conjunction:
            #   captured sym key ≥ 1 ∧ sym encrypt event ∧
            #   decryption_essentials.json present
            # (captured key may be a keygen/kdf sym_key OR a key captured at the
            #  RSA-wrap input — the PayBreak escrow point — see
            #  captured_symmetric_keys_at_least.)
            {"primitive": "captured_symmetric_keys_at_least", "kwargs": {"n": 1}},
            {"primitive": "has_any_event",
              "kwargs": {"apis": ["BCryptEncrypt", "BCryptDecrypt",
                                    "CryptEncrypt", "CryptDecrypt",
                                    "EVP_EncryptUpdate", "EVP_DecryptUpdate",
                                    "AES_encrypt", "AES_decrypt",
                                    "AES_start_operation",
                                    "ARC4_stream_init", "chacha20_init",
                                    "Salsa20_stream_init"]}},
            {"primitive": "file_present",
              "kwargs": {"rel_path": "decryption_essentials.json"}},
        ],
    },
]


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------
def _resolve(spec: dict) -> Callable:
    name = spec.get("primitive")
    factory = PRIMITIVE_FACTORY.get(name)
    if factory is None:
        raise KeyError(f"unknown primitive: {name}")
    return factory(**(spec.get("kwargs") or {}))


def evaluate(ctx: dict) -> dict:
    """Run every RC case against the prepared ctx.  Returns:

        {
          "passed":  [ {case_id, strategy, confidence, ...}, ... ],
          "failed":  [ {case_id, blocking_evidence: [...]}, ... ],
          "feasible_strategies": [strategy, ...],
          "support_status": "OK" | "DEGRADED" | "BLOCKED",
        }

    support_status =
        OK        if every case's blocking primitives are answerable
                  (every required primitive resolves to OK or DEGRADED)
        DEGRADED  if any DEGRADED primitive was on a passing case's path
        BLOCKED   if at least one UNAVAILABLE primitive is in play
                  (typically: residue / buffer-bytes cases)
    """
    passed: list = []
    failed: list = []
    saw_unavailable = False
    saw_degraded = False

    for case in CASES:
        ev_results = []
        all_ok = True
        case_degraded = False
        for spec in case["evidence_required"]:
            check = _resolve(spec)
            ok, observed, support = check(ctx)
            if support == "UNAVAILABLE":
                saw_unavailable = True
            elif support == "DEGRADED":
                case_degraded = True
            ev_results.append({
                "primitive": spec["primitive"],
                "kwargs":    spec.get("kwargs") or {},
                "observed":  observed,
                "support":   support,
                "ok":        ok,
            })
            if not ok:
                all_ok = False
        record = {
            "case_id":            case["case_id"],
            "name":               case["name"],
            "strategy":           case["strategy"],
            "confidence_when_met": case["confidence_when_met"],
            "description":        case["description"],
            "real_samples":       case["real_samples"],
            "evidence":           ev_results,
        }
        if all_ok:
            passed.append(record)
            # DEGRADED counts only when the degraded primitive was on a
            # *passing* case's path, per the support_status contract above.
            if case_degraded:
                saw_degraded = True
        else:
            blocking = [e for e in ev_results if not e["ok"]]
            record["blocking_evidence"] = blocking
            failed.append(record)

    support_status = "OK"
    if saw_unavailable:
        support_status = "BLOCKED"
    elif saw_degraded:
        support_status = "DEGRADED"

    return {
        "passed":               passed,
        "failed":               failed,
        "feasible_strategies":  sorted({c["strategy"] for c in passed}),
        "passed_count":         len(passed),
        "total_cases":          len(CASES),
        "support_status":       support_status,
    }
