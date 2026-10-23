"""Materialize the analysis into `analysis_report.json`, `case_study.md`,
and `behavior_profile.txt` — the three artifacts the legacy pipeline
also produced (minus the bundle ZIP).

Everything fed in is pre-computed; this module is JSON/Markdown only.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from . import disasm


# atomic + LF-only writer so JSON/MD artifacts have
# stable bytes across Windows/Linux (no CRLF translation) and survive a
# mid-write crash (tmp + os.replace).
def _atomic_write_text(out_path: str, text: str) -> None:
    # out_path is taken from caller without validation; in
    # defensive tooling, require the resolved path to be inside an explicit
    # allowed reports root (RANSACK_REPORTS_ROOT) when that env var is set.
    # When unset, fall through and trust the caller (documented contract).
    _allowed_root = os.environ.get("RANSACK_REPORTS_ROOT")
    if _allowed_root:
        _abs_out = os.path.realpath(out_path)
        _abs_root = os.path.realpath(_allowed_root)
        if os.path.commonpath([_abs_out, _abs_root]) != _abs_root:
            raise ValueError(
                f"_atomic_write_text refused out_path={out_path!r}: "
                f"not under RANSACK_REPORTS_ROOT={_allowed_root!r}")
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
        f.flush()
        try:
            os.fsync(f.fileno())
        except (OSError, AttributeError):
            # fsync may not be available on every filesystem (e.g. some
            # network mounts); the os.replace below is still atomic on
            # POSIX and on Windows >= NTFS so the artifact never appears
            # truncated to a downstream consumer.
            pass
    os.replace(tmp, out_path)


# ---------------------------------------------------------- JSON
def write_analysis_report(out_path: str, *,
                           bundle: dict,
                           loop_labels: dict,
                           io_summary: dict,
                           crypto_summary: dict,
                           stage_profile: dict,
                           recovery: dict | None = None,
                           residue: dict | None = None,
                           cipher_constants: dict | None = None,
                           sym_key_inference: dict | None = None,
                           wrapped_key_inference: dict | None = None,
                           cross_axis: dict | None = None,
                           chain: dict | None = None,
                           clusters: dict | None = None,
                           byte_sigs: dict | None = None) -> None:
    # Strip the big per-loop snapshot bytes / capstone listings from the
    # JSON — they live in the .bin/.meta originals. Keep label + activity
    # only.
    compact_loops = {}
    # bundle['loops'] direct indexing → .get() fallback so a
    # malformed/empty bundle does not raise KeyError and break the whole report.
    for lid, L in (bundle.get("loops") or {}).items():
        # normalize lid to str at the boundary so both the
        # compact_loops key and the cluster_id lookup use the same key type;
        # PinTool emits int lid in some versions, str in others.
        lid_key = str(lid)
        cls = loop_labels.get(lid, {})
        d   = L.get("_disasm") or {}
        compact_loops[lid_key] = {
            "loop_id":         lid,
            "header":          L.get("header"),
            "backedge":        L.get("backedge"),
            "loop_end":        L.get("loop_end"),
            "range_size":      L.get("range_size"),
            "iteration_at_capture": L.get("iteration_at_capture"),
            "final_iterations":     L.get("final_iterations"),
            "image_path":      L.get("image_path"),
            "image_module":    cls.get("image_module"),
            "image_role":      cls.get("image_role"),
            "routine_name":    L.get("routine_name"),
            "instruction_count_meta":   L.get("instruction_count"),
            "instruction_count_disasm": d.get("instruction_count_disasm"),
            "control_transfer_count":   len(L.get("control_transfer_refs") or []),
            "label":           cls.get("label"),
            "category":        cls.get("category"),
            "confidence":      cls.get("confidence"),
            "corroboration":   cls.get("corroboration") or {},
            # look up loop_to_cluster by the same normalized
            # str key used for compact_loops, with raw-lid fallback so older
            # bundles that key clusters by int still resolve.
            "cluster_id":      ((clusters or {}).get("loop_to_cluster", {}).get(lid_key)
                                  if (clusters or {}).get("loop_to_cluster", {}).get(lid_key) is not None
                                  else (clusters or {}).get("loop_to_cluster", {}).get(lid)),
            "activity":        cls.get("activity"),
            "io_summary":      io_summary.get("per_loop", {}).get(lid, {}),
            "crypto_summary":  crypto_summary.get("per_loop", {}).get(lid, {}),
            "apis_called_in_loop": d.get("apis_called") or [],
            "matches":             cls.get("matches", []),
            "suppressed_crypto":   cls.get("suppressed_crypto", []),
        }

    out = {
        "_meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "trace_dir":    bundle.get("trace_dir"),
            "main_exe":     bundle.get("main_exe"),
        },
        "runtime": {
            "seconds":              bundle.get("runtime_seconds"),
            "peak_working_set_bytes": bundle.get("peak_working_set_bytes"),
        },
        "loaded_dlls": {
            "count": bundle.get("dll_count"),
            "list":  [d.get("base_name") for d in (bundle.get("dlls") or [])],
        },
        "behavior_profile": stage_profile,
        "recovery_cases":   recovery or {},
        "residue":          residue or {},
        "cipher_constants": cipher_constants or {},
        "sym_key_inference": sym_key_inference or {},
        "wrapped_key_inference": wrapped_key_inference or {},
        "cross_axis":       cross_axis or {},
        "chain":            chain or {},
        "loop_clusters":    clusters or {},
        "byte_signatures":  byte_sigs or {},
        "io_global":     {k: v for k, v in io_summary.items() if k != "per_loop"},
        "crypto_global": {k: v for k, v in crypto_summary.items() if k != "per_loop"},
        "loops": compact_loops,
    }
    # route through _atomic_write_text so the JSON has
    # LF-only line endings (no Windows CRLF translation) and is written
    # atomically (tmp + os.replace) — downstream report.adapter
    # never sees a truncated/half-written file.
    _atomic_write_text(
        out_path,
        json.dumps(out, indent=2, ensure_ascii=False))


# ---------------------------------------------------------- behavior_profile.txt
def write_behavior_profile(out_path: str, stage_profile: dict) -> None:
    from . import stage_profile as sp
    # atomic + LF-only write (see _atomic_write_text).
    _atomic_write_text(out_path, sp.render_text(stage_profile) + "\n")


# ---------------------------------------------------------- report.md (at-a-glance)
def _humanise_bytes(n) -> str:
    # coerce n to float at the top so the unit-special-case
    # branch is no longer needed and the running division does not silently
    # change type partway through the loop.
    try:
        n = float(int(n))
    except (TypeError, ValueError):
        return "?"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _top_corroborated_labels(loop_labels: dict, limit: int = 3) -> list[dict]:
    """Pick the most analytically valuable loops: corroborated/byte_gated,
    PLUS high-confidence deterministic crypto patterns. A pattern whose
    mnemonic IS the algorithm (AES-NI `aesenc`, bignum modexp, software S-box
    table lookups) is self-evidencing — it needs no S2/S3 corroboration to be
    a valid cipher identification. Hash patterns (SHA/MD5/BLAKE) are excluded
    since a hash is not a cipher. (keeps decisive AES-NI /
    bignum signatures from being dropped merely because they are pattern_only.)"""
    rows = []
    for lid, cls in loop_labels.items():
        corr = cls.get("corroboration") or {}
        verdict = corr.get("verdict")
        label = cls.get("label") or ""
        conf = float(cls.get("confidence") or 0.0)
        # substring check on ('sha','md5','blake','hash')
        # also matched 'crypto.hashtable_walk', 'crypto.rehash_table' etc.
        # which are utility loops, not hash functions. Parse the dotted
        # label as 'crypto.<category>.<algo>' and only treat the *algo*
        # token as a hash family. Fall back to a word-boundary check on
        # the trailing component so historical 2-segment labels
        # ('crypto.sha256_round') still classify correctly.
        import re as _re
        _hash_tokens = {"sha", "sha1", "sha2", "sha256", "sha512",
                        "md5", "md4", "blake", "blake2", "blake3",
                        "keccak", "ripemd", "hash"}
        _segs = label.split(".")
        _algo_seg = _segs[-1] if len(_segs) >= 2 else ""
        _algo_tokens = set(_re.split(r"[^A-Za-z0-9]+", _algo_seg.lower()))
        _is_hash_label = bool(_algo_tokens & _hash_tokens)
        is_deterministic = (
            label.startswith("crypto.") and conf >= 0.7
            and not _is_hash_label)
        if verdict in ("corroborated", "byte_gated") or \
           (verdict == "pattern_only" and is_deterministic):
            rows.append({
                "loop_id": lid,
                "label":   label,
                "conf":    cls.get("confidence"),
                "verdict": verdict,
                "s2_hits": corr.get("s2_hits") or [],
                "s3_hits": corr.get("s3_hits") or [],
            })
    # coerce confidence via a single helper so a string
    # confidence (e.g. '0.85' from JSON-loaded bundles) does not raise
    # TypeError under the negation-for-descending sort.
    def _f(v):
        try:
            return float(v) if v is not None and v != "" else 0.0
        except (TypeError, ValueError):
            return 0.0
    rows.sort(key=lambda r: -_f(r["conf"]))
    return rows[:limit]


def _closest_rcs(recovery: dict, limit: int = 3) -> list[dict]:
    """Return the failed RCs that came closest to passing — measured by
    how few primitives blocked them."""
    failed = (recovery or {}).get("failed") or []
    enriched = []
    # defensive .get() on rc fields so a partially-filled
    # failed entry (missing case_id/name/blocking_evidence schema) does not
    # KeyError and kill the whole report. Sort still keys on case_id so the
    # ordering is stable.
    for r in failed:
        block = r.get("blocking_evidence") or []
        first_block = block[0] if block else {}
        enriched.append({
            "case_id":   r.get("case_id") or "?",
            "name":      r.get("name") or "?",
            "blocks":    len(block),
            "top_block": (first_block.get("observed") if first_block else None) or "—",
            "primitive": (first_block.get("primitive") if first_block else None) or "—",
        })
    # case_id == '?' must sort to the bottom; with plain
    # lexicographic comparison '?' (0x3F) sorts before 'R' so partial RCs
    # would surface above real RC-NN ids. Push '?' last via a tuple key.
    enriched.sort(key=lambda r: (r["blocks"], r["case_id"] == "?", r["case_id"]))
    return enriched[:limit]


def write_report(out_path: str, *,
                  bundle: dict,
                  loop_labels: dict,
                  io_summary: dict,
                  crypto_summary: dict,
                  stage_profile: dict,
                  recovery: dict | None = None,
                  residue: dict | None = None,
                  cipher_constants: dict | None = None,
                  cross_axis: dict | None = None,
                  chain: dict | None = None,
                  clusters: dict | None = None,
                  byte_sigs: dict | None = None) -> None:
    """Short human-readable report — the single file an analyst opens first."""
    lines: list[str] = []

    main_exe = bundle.get("main_exe")
    if main_exe:
        base = os.path.basename(main_exe)
    else:
        # PinTool sometimes omits loaded_dlls.json (short captures); fall
        # back to the trace dir basename so the header still identifies
        # the sample.
        base = os.path.basename(bundle.get("trace_dir", "") or "") or "(unknown sample)"

    # ── 1) Header
    lines.append(f"# {base}")
    lines.append("")
    dll_count = bundle.get("dll_count") or 0
    # bind bundle.get('runtime_seconds') once; previously
    # called twice which was brittle and read the dict in two places.
    _rs = bundle.get("runtime_seconds")
    runtime_str = (f"{_rs} s" if _rs is not None else "? s")
    runtime_extras = [f"peak WSS {_humanise_bytes(bundle.get('peak_working_set_bytes'))}"]
    if dll_count:
        runtime_extras.append(f"{dll_count} DLLs loaded")
    lines.append(
        f"- **Runtime:** {runtime_str} · " + " · ".join(runtime_extras))

    # Recovery one-liner
    sup = (recovery or {}).get("support_status", "?")
    passed = (recovery or {}).get("passed_count", 0)
    total  = (recovery or {}).get("total_cases", 7)
    feas   = (recovery or {}).get("feasible_strategies") or []
    if feas:
        feas_str = ", ".join(f"`{s}`" for s in feas)
        rec_line = f"**Recoverable via {feas_str}** ({passed}/{total} cases pass)"
    else:
        rec_line = f"**BLOCKED** — {passed}/{total} cases pass · status `{sup}`"
    lines.append(f"- **Recovery:** {rec_line}")
    lines.append("")

    # ── 2) TL;DR — one short paragraph
    chain_stats = (chain or {}).get("stats") or {}
    n_nodes = chain_stats.get("node_count", 0)
    n_sinks = chain_stats.get("sink_count", 0)
    n_src   = chain_stats.get("source_count", 0)
    ratio   = chain_stats.get("hardcoded_key_ratio", 0.0)
    cipher_status = (cipher_constants or {}).get("status", "skipped")
    # n_const_hits was computed but never read; surface it
    # in the TL;DR so the byte-constant gate count is visible to the analyst.
    try:
        n_const_hits = sum(
            int(v or 0)
            for v in ((cipher_constants or {}).get("by_constant") or {}).values())
    except (TypeError, ValueError):
        n_const_hits = 0
    cluster_stats = (clusters or {}).get("stats") or {}
    n_in  = cluster_stats.get("input_loops", 0)
    n_out = cluster_stats.get("cluster_count", 0)
    # removed dead `s5 = ((bundle.get('loops') or {}),)`
    # tuple — it was never read and collided with the legitimate `s5`
    # (stage5_fileops) usage further down in this same function. The
    # surviving stage5 binding has been renamed to `s5_fileops` to make
    # the name collision impossible to re-introduce by accident.
    top_corr = _top_corroborated_labels(loop_labels, limit=1)
    if top_corr:
        cipher_phrase = (
            f"`{top_corr[0]['label']}` (conf={top_corr[0]['conf']}, "
            f"{top_corr[0]['verdict']})")
    elif cipher_status == "detected":
        # Find dominant CIPHER from cipher_constants if cross-axis didn't
        # fire. Hashes (SHA/BLAKE/MD5/RIPEMD/Keccak) are not ciphers, and
        # ambiguous shared constants are already excluded from by_constant
        # upstream — so this only surfaces a concrete symmetric/asym cipher.
        _HASH = ("sha", "md5", "ripemd", "blake", "keccak")
        # A *pure* hash is excluded. But RSA-PKCS/SHA-256 style OIDs (a
        # cipher token leads the algo name) must NOT be dropped just because
        # "sha" appears later in the string.
        _CIPHER = ("rsa", "aes", "des", "rc4", "rc5", "rc6", "chacha",
                   "salsa", "tea", "blowfish", "twofish", "serpent",
                   "camellia", "ecc", "curve", "25519", "seed", "aria",
                   "kuznyechik", "gost", "idea", "cast")

        # substring containment on _CIPHER caused
        # 'tea' (3-letter cipher token) to match identifiers like
        # 'feature_extractor', 'creature_walk', 'plateau_loop'; the algo
        # label was then mis-classified as a cipher and the pure-hash
        # exclusion was defeated. Tokenize on non-alphanumerics and
        # require an EXACT token match against either set.
        import re as _re_ciph

        def _is_pure_hash(a: str) -> bool:
            toks = set(_re_ciph.split(r"[^A-Za-z0-9]+", a.lower()))
            return (not (toks & set(_CIPHER))) and bool(toks & set(_HASH))

        by = (cipher_constants or {}).get("by_constant") or {}
        cipher_by = {k: v for k, v in by.items()
                     if not _is_pure_hash(k.split("::")[0])}
        if cipher_by:
            # `max(cipher_by, key=cipher_by.get)` would
            # raise TypeError in Py3 if any value were None (comparison
            # between int and NoneType). Coerce missing counts to 0 via
            # .items() so the hottest cipher constant is always pickable.
            algo = max(cipher_by.items(),
                       key=lambda kv: kv[1] or 0)[0].split("::")[0]
            cipher_phrase = f"`{algo}` via byte-constant gate only"
        else:
            cipher_phrase = "*no cipher identified (hash/ambiguous constants only)*"
    else:
        cipher_phrase = "*no cipher identified*"

    chain_phrase = (
        f"{n_nodes} chain node(s), {n_sinks} sink(s), "
        f"{n_src} RNG source(s)" if n_nodes else "no chain (no hooked crypto APIs)")
    lines.append("## TL;DR")
    lines.append("")
    lines.append(
        f"Cipher identified: {cipher_phrase}.  "
        f"Key flow: {chain_phrase}.  "
        f"{n_in} loops → {n_out} unique behaviors.  "
        f"{rec_line}.")
    lines.append("")

    # ── 3) Cipher detection
    lines.append("## Cipher detection")
    lines.append("")
    if top_corr:
        lines.append("| loop | label | verdict | conf | byte-gate algos |")
        lines.append("|---|---|---|---|---|")
        for r in top_corr:
            s3 = ", ".join(r["s3_hits"]) or "—"
            lines.append(
                f"| {r['loop_id']} | `{r['label']}` | "
                f"`{r['verdict']}` | {r['conf']} | {s3} |")
    else:
        lines.append("*No loop label survived Step 3 corroboration.*")
    by_const = (cipher_constants or {}).get("by_constant") or {}
    if by_const:
        lines.append("")
        # coerce hit counts to int with try/except so a
        # stringified or None count in by_constant does not raise TypeError
        # under the descending sort.
        def _ci(v):
            try:
                return int(v or 0)
            except (TypeError, ValueError):
                return 0
        lines.append(
            "Byte-constant hits: " +
            ", ".join(f"`{k}` ×{v}"
                       for k, v in sorted(by_const.items(),
                                            key=lambda kv: -_ci(kv[1]))[:5]))
    lines.append("")

    # ── 4) Key flow
    lines.append("## Key flow")
    lines.append("")
    if n_nodes:
        lines.append(
            f"- chain: **{n_nodes} nodes**, "
            f"{chain_stats.get('edge_count', 0)} edges, "
            f"{n_src} src · {n_sinks} sinks · "
            f"{chain_stats.get('embedded_root_count', 0)} embedded roots · "
            f"depth {chain_stats.get('max_chain_depth', 0)}")
        if n_sinks:
            lines.append(
                f"- hardcoded_key_ratio = **{ratio:.2f}** "
                f"({chain_stats.get('sinks_without_rng_ancestor', 0)}/"
                f"{n_sinks} sinks fed by embedded roots)")
        if chain_stats.get("rng_to_keygen_path_count", 0):
            lines.append(
                f"- {chain_stats['rng_to_keygen_path_count']} rng→keygen "
                f"path(s) — RC-05 evidence")
    else:
        lines.append(
            "*No key derivation chain — sample did not call hooked crypto "
            "APIs (probably inline crypto). Cipher identification falls "
            "back to byte-constant gate only.*")
    res_class = (residue or {}).get("residue_class", "NONE")
    res_matches = (residue or {}).get("total_matches", 0)
    res_scanned = (residue or {}).get("snapshots_scanned", 0)
    lines.append(
        f"- residue tier: **{res_class}** "
        f"({res_matches} matches across {res_scanned} key-birth snapshots)")
    promo = (residue or {}).get("byte_sig_promotion")
    if promo:
        # switch to .get() with safe defaults so a missing
        # 'from'/'to'/'reasons' field does not KeyError the whole report.
        _reasons = promo.get("reasons") or []
        lines.append(
            f"  - promoted {promo.get('from', '?')} -> {promo.get('to', '?')} "
            f"by byte-signature scanners: {', '.join(_reasons)}")
    bs = byte_sigs or {}
    if bs.get("snapshots_scanned"):
        bs_line = (
            f"- byte signatures (verbatim ports of published recovery research): "
            f"aeskeyfind={bs.get('aeskeyfind_count', 0)} (Halderman 2008) · "
            f"bcrypt_rsa_blob={bs.get('bcrypt_rsa_blob_count', 0)} (MS CNG verbatim) · "
            f"cryptoapi_rsa_blob={bs.get('cryptoapi_rsa_blob_count', 0)} (MS CryptoAPI PRIVATEKEYBLOB) · "
            f"avaddon_session={bs.get('avaddon_session_count', 0)} (Yuste 2021) · "
            f"wanakiwi_prime={bs.get('wanakiwi_prime_count', 0)} (Guinet 2017, "
            f"{bs.get('rsa_moduli_in_chain', 0)} modulus candidate(s)) · "
            f"{bs.get('snapshots_scanned', 0)} snapshots scanned")
        lines.append(bs_line)
    lines.append("")

    # ── 5) Loop behavior
    lines.append("## Loop behavior")
    lines.append("")
    big = cluster_stats.get("largest_cluster") or {}
    lines.append(
        f"- {n_in} captured loops → **{n_out} unique clusters** "
        f"(compaction {cluster_stats.get('compaction_ratio', 0.0):.2f})")
    if big:
        lines.append(
            f"- largest cluster: **{big.get('loop_count')}× "
            f"`{big.get('label')}`**")
    # File ops one-liner — pulled from the stage_profile (stage5_fileops),
    # which carries the open/read/write/delete/move semantic counts. The
    # raw io_summary.by_kind only has in/out byte direction.
    # renamed local from `s5` to `s5_fileops` to remove
    # the historical name collision with the deleted dead-code tuple.
    s5_fileops = (stage_profile or {}).get("stage5_fileops") or {}
    lines.append(
        f"- file ops: open {s5_fileops.get('opens', 0):,} · "
        f"read {s5_fileops.get('reads', 0):,} · "
        f"write {s5_fileops.get('writes', 0):,} · "
        f"delete {s5_fileops.get('deletes', 0)} · "
        f"move {s5_fileops.get('moves', 0)}")
    lines.append("")

    # ── 6) Recovery — closest RCs
    lines.append("## Recovery cases — closest to passing")
    lines.append("")
    closest = _closest_rcs(recovery, limit=3)
    passed_list = (recovery or {}).get("passed") or []
    if passed_list:
        lines.append("**Passed:** " +
                      ", ".join(f"`{r['case_id']} {r['name']}`"
                                  for r in passed_list))
        lines.append("")
    if closest:
        lines.append("| case | name | blocked by |")
        lines.append("|---|---|---|")
        for r in closest:
            lines.append(
                f"| `{r['case_id']}` | {r['name']} | "
                f"`{r['primitive']}`: {r['top_block']} |")
    else:
        lines.append("*No recovery cases defined.*")
    lines.append("")

    # ── 7) See also
    lines.append("## See also")
    lines.append("")
    lines.append("- `_detail/case_study.md` — full per-loop breakdown, "
                  "cluster table, complete RC matrix, cross-axis verdicts")
    lines.append("- `_detail/analysis_report.json` — machine-readable, "
                  "all evidence streams")
    lines.append("- `_detail/behavior_profile.txt` — 5-stage narrative")
    lines.append("")

    # atomic + LF-only write (see _atomic_write_text).
    _atomic_write_text(out_path, "\n".join(lines))


# ---------------------------------------------------------- case_study.md
def _sort_key_loop(L: dict, cls: dict, io_sum: dict, cs_sum: dict,
                    main_exe_base: str) -> tuple:
    """Deterministic sort key for ranking loops by analytical value.

    Priority (descending):
      1. crypto-labeled loop (bool)
      2. classifier confidence (float, higher is better)
      3. final iteration count (higher is more active)
      4. loop lives in the sample's own image (bool)
    All fields come directly from the classifier or PinTool measurement;
    no ad-hoc weights are applied.
    """
    label = cls.get("label", "") or ""
    cat   = cls.get("category", "") or ""
    # substring `'crypto' in label` matched utility
    # loops like 'micrypto_dummy' while missing 'decrypt' (no 'crypto'
    # substring). Tighten to the canonical dotted-prefix the classifier
    # actually emits.
    is_crypto = label.startswith("crypto.") or cat.startswith("crypto.")
    confidence = float(cls.get("confidence") or 0.0)
    iters = int(L.get("final_iterations") or cls.get("iters") or 0)
    in_main = bool(main_exe_base and cls.get("image_module") == main_exe_base)
    # negate numeric fields so sorted() ascending == highest-value first
    return (not is_crypto, -confidence, -iters, not in_main)


def write_case_study(out_path: str, *,
                       bundle: dict,
                       loop_labels: dict,
                       io_summary: dict,
                       crypto_summary: dict,
                       stage_profile: dict,
                       recovery: dict | None = None,
                       cipher_constants: dict | None = None,
                       sym_key_inference: dict | None = None,
                       cross_axis: dict | None = None,
                       chain: dict | None = None,
                       clusters: dict | None = None) -> None:
    main_exe_base = os.path.basename(bundle.get("main_exe") or "").lower()

    ranked = []
    # defensive .get() to keep the case-study report alive
    # if 'loops' is missing or None.
    for lid, L in (bundle.get("loops") or {}).items():
        cls    = loop_labels.get(lid, {})
        io_sum = io_summary.get("per_loop", {}).get(lid, {})
        cs_sum = crypto_summary.get("per_loop", {}).get(lid, {})
        k = _sort_key_loop(L, cls, io_sum, cs_sum, main_exe_base)
        ranked.append((k, lid, L, cls, io_sum, cs_sum))
    ranked.sort(key=lambda x: (x[0], x[1]))

    lines = []
    lines.append(f"# Case Study — {bundle.get('main_exe') or '(unknown sample)'}")
    lines.append("")
    lines.append("> Generated by `Ransack/onHost/analysis/analyze_trace.py`. "
                 "Inputs: PinTool loop/io/crypto JSONLs + snapshot.bins.")
    lines.append("")
    lines.append(f"- **Runtime**: {bundle.get('runtime_seconds')} s, "
                 f"peak WSS = {bundle.get('peak_working_set_bytes')} B")
    # defensive .get() so a partial stage_profile (when
    # the core collector exits early) does not KeyError the case study.
    s3 = stage_profile.get("stage3_loops") or {}
    lines.append(f"- **Loops**: {s3.get('total_hot_loops', 0)} total, "
                 f"{len(s3.get('crypto_label_loops') or [])} crypto-labeled, "
                 f"{len(s3.get('io_loops') or [])} did IO, "
                 f"{len(s3.get('crypto_call_loops') or [])} called a crypto API")
    s4 = stage_profile.get("stage4_encrypt") or {}
    lines.append(f"- **Encrypt APIs observed**: sym={s4.get('sym_apis', 0)} "
                 f"asym={s4.get('asym_apis', 0)} memop_calls={s4.get('memop_calls', 0)}")
    s5 = stage_profile.get("stage5_fileops") or {}
    lines.append(f"- **File ops**: opens={s5.get('opens', 0)} reads={s5.get('reads', 0)} "
                 f"writes={s5.get('writes', 0)} deletes={s5.get('deletes', 0)} "
                 f"moves={s5.get('moves', 0)}")
    cov = stage_profile.get("coverage", {})
    if cov.get("notes"):
        lines.append("- **Coverage notes**: " + ", ".join(cov["notes"]))
    lines.append("")

    # ── Recovery-case matrix
    if recovery:
        lines.append("## Recovery cases (RC-01..RC-07)")
        lines.append("")
        lines.append(f"- Support status: **{recovery.get('support_status')}**  "
                     f"({recovery.get('passed_count')}/"
                     f"{recovery.get('total_cases')} cases passed)")
        feas = recovery.get("feasible_strategies") or []
        lines.append(f"- Feasible strategies: "
                     f"{', '.join('`'+s+'`' for s in feas) if feas else '(none)'}")
        lines.append("")
        lines.append("| case | name | strategy | conf | result | blocking evidence |")
        lines.append("|---|---|---|---|---|---|")
        seen = set()
        # defensive .get() for each RC field so a missing
        # field in any rec dict does not crash the entire report table.
        for rec in (recovery.get("passed") or []):
            cid = rec.get("case_id") or "?"
            seen.add(cid)
            lines.append(
                f"| `{cid}` | {rec.get('name') or '?'} | "
                f"`{rec.get('strategy') or '?'}` | "
                f"{rec.get('confidence_when_met') or '?'} | "
                f"**PASS** | — |")
        for rec in (recovery.get("failed") or []):
            cid = rec.get("case_id") or "?"
            seen.add(cid)
            blocking = rec.get("blocking_evidence") or []
            blocking_str = "; ".join(
                f"`{e.get('primitive') or '?'}`: {e.get('observed') or '?'} "
                f"({e.get('support') or '?'})" for e in blocking[:2])
            if len(blocking) > 2:
                blocking_str += f" (+{len(blocking)-2} more)"
            lines.append(
                f"| `{cid}` | {rec.get('name') or '?'} | "
                f"`{rec.get('strategy') or '?'}` | "
                f"{rec.get('confidence_when_met') or '?'} | "
                f"fail | {blocking_str} |")
        lines.append("")

    # ── Cross-axis corroboration (paper §III Step 3)
    if cross_axis is not None:
        lines.append("## Cross-axis corroboration (Step 3)")
        lines.append("")
        vc = cross_axis.get("verdict_counts") or {}
        total = sum(vc.values())
        lines.append(f"- Loops examined: **{total}**  "
                     f"corroborated={vc.get('corroborated', 0)}, "
                     f"byte_gated={vc.get('byte_gated', 0)}, "
                     f"pattern_only={vc.get('pattern_only', 0)}, "
                     f"downgraded={vc.get('downgraded', 0)}, "
                     f"not_applicable={vc.get('not_applicable', 0)}")

        downs = cross_axis.get("downgrades") or []
        if downs:
            lines.append("")
            lines.append("### Pattern-only labels downgraded by Step 3")
            lines.append("")
            lines.append("| loop | from | → | reason |")
            lines.append("|---|---|---|---|")
            for d in downs:
                lines.append(
                    f"| {d['loop_id']} | `{d['from_label']}` "
                    f"(conf={d['from_confidence']}) | `unknown.utility` | "
                    f"{d['reason']} |")

        ulev = cross_axis.get("unlabelled_evidence") or []
        if ulev:
            lines.append("")
            lines.append("### Loops with key/byte evidence but no crypto pattern label")
            lines.append("")
            lines.append("(structural matcher returned `unknown.utility` — "
                         "but co-located crypto events or cipher constants "
                         "suggest the loop is crypto-relevant; review)")
            lines.append("")
            lines.append("| loop | label | crypto calls | byte-const hits |")
            lines.append("|---|---|---|---|")
            for u in ulev[:15]:
                # defensive .get() on byte_const_hits and
                # related u[...] fields so an entry missing the field does
                # not KeyError the entire report.
                hits = ", ".join(sorted({a for a in (u.get("byte_const_hits") or []) if a})) or "—"
                lines.append(
                    f"| {u.get('loop_id', '?')} | `{u.get('pattern_label', '?')}` | "
                    f"{u.get('crypto_calls', 0)} | {hits} |")
        lines.append("")

    # ── Key derivation chain graph (paper §III)
    if chain is not None:
        lines.append("## Key derivation chain graph")
        lines.append("")
        cs = chain.get("stats") or {}
        lines.append(
            f"- nodes={cs.get('node_count', 0)}, "
            f"edges={cs.get('edge_count', 0)}, "
            f"sources={cs.get('source_count', 0)}, "
            f"sinks={cs.get('sink_count', 0)}, "
            f"embedded_roots={cs.get('embedded_root_count', 0)}, "
            f"depth={cs.get('max_chain_depth', 0)}")
        if cs.get("sink_count", 0):
            lines.append(
                f"- sinks reachable from an RNG source: "
                f"{cs.get('sinks_with_rng_ancestor', 0)} / "
                f"{cs.get('sink_count', 0)}; "
                f"hardcoded_key_ratio = "
                f"**{cs.get('hardcoded_key_ratio', 0.0):.2f}** "
                f"(higher → more sinks fed by embedded-root tags)")
        if cs.get("rng_to_keygen_path_count", 0):
            lines.append(
                f"- rng→keygen reachability paths: "
                f"{cs.get('rng_to_keygen_path_count')} "
                f"(RC-05 evidence — weak entropy feeding key derivation)")

        edges = chain.get("edges") or []
        if edges:
            edges = sorted(edges, key=lambda e: -e.get("count", 0))[:15]
            lines.append("")
            lines.append("### Top derivation edges (by call count)")
            lines.append("")
            lines.append("| parent → child | api | kind | count | in/out len |")
            lines.append("|---|---|---|---|---|")
            # harden every edge field with .get() defaults
            # so a missing field in an upstream-produced edge entry does not
            # KeyError the whole case study.
            for e in edges:
                lines.append(
                    f"| {e.get('parent', '?')} → {e.get('child', '?')} | "
                    f"`{e.get('api', '?')}` | {e.get('kind', '?')} | {e.get('count', 0)} | "
                    f"{e.get('in_len_total', 0)}/{e.get('out_len_total', 0)} |")
        lines.append("")

    # ── Cipher constants (loop-immediate magic-byte scan)
    if cipher_constants is not None:
        lines.append("## Cipher constants")
        lines.append("")
        status = cipher_constants.get("status", "skipped")
        lines.append(f"- Status: **{status}**")
        if cipher_constants.get("reason"):
            lines.append(f"- Reason: {cipher_constants['reason']}")
        by_const = cipher_constants.get("by_constant") or {}
        if by_const:
            lines.append("")
            lines.append("| algo::constant | hits |")
            lines.append("|---|---|")
            for k, v in sorted(by_const.items(), key=lambda kv: (-kv[1], kv[0])):
                lines.append(f"| `{k}` | {v} |")
        lines.append("")

    # ── Symmetric key algorithm inference
    if sym_key_inference is not None:
        lines.append("## Symmetric key inference")
        lines.append("")
        si = sym_key_inference
        dominant = "(none)"
        by = si.get("by_inferred_algo") or {}
        if by:
            dominant = max(by, key=by.get)
        lines.append(f"- Inferred dominant algorithm: `{dominant}`")
        lines.append(f"- Rules loaded: {si.get('rules_loaded', 0)}; "
                     f"keys total={si.get('total_keys', 0)}, "
                     f"with explicit algorithm={si.get('with_algorithm_in', 0)}, "
                     f"newly inferred={si.get('inferred', 0)}")
        if by:
            lines.append("")
            lines.append("| inferred algo | keys |")
            lines.append("|---|---|")
            for algo, n in sorted(by.items(), key=lambda kv: (-kv[1], kv[0])):
                lines.append(f"| `{algo}` | {n} |")
        lines.append("")

    # ── Loop clusters (structural fingerprint compaction)
    if clusters is not None:
        lines.append("## Loop clusters")
        lines.append("")
        st = clusters.get("stats") or {}
        big = st.get("largest_cluster") or {}
        lines.append(
            f"- {st.get('input_loops', 0)} captured loop instances → "
            f"**{st.get('cluster_count', 0)} unique structural clusters** "
            f"(compaction ratio "
            f"{st.get('compaction_ratio', 0.0):.2f})")
        if big:
            lines.append(
                f"- largest cluster: **{big.get('loop_count', 0)}× "
                f"`{big.get('label')}`** "
                f"(cluster `{big.get('cluster_id')}`)")
        cl = list((clusters.get("clusters") or {}).values())
        if cl:
            # defensive sort key — coerce missing/None
            # total_iters/loop_count to 0 and label to '' so a partial cluster
            # entry does not raise TypeError.
            cl.sort(key=lambda c: (-(c.get("total_iters") or 0),
                                     -(c.get("loop_count") or 0),
                                     c.get("label") or ""))
            lines.append("")
            lines.append(
                "### Per-cluster summary (sorted by total iters)")
            lines.append("")
            lines.append("| cluster | n× | label | image | conf | "
                         "total iters | range | header | mnemonics |")
            lines.append("|---|---|---|---|---|---|---|---|---|")
            for c in cl[:50]:
                act = c.get("activity") or {}
                _ = act  # activity intentionally omitted to keep row narrow
                mh = c.get("mnemonic_head") or ""
                if len(mh) > 60:
                    mh = mh[:60] + "…"
                lines.append(
                    f"| `{c['cluster_id']}` | "
                    f"{c['loop_count']} | "
                    f"`{c['label']}` | "
                    f"`{c['image_module'] or '?'}` | "
                    f"{c.get('confidence') if c.get('confidence') is not None else '—'} | "
                    f"{c['total_iters']:,} | "
                    f"{c['range_size']}B | "
                    f"`{c.get('header') or '?'}` | "
                    f"`{mh}` |")
            if len(cl) > 50:
                lines.append(f"\n(+{len(cl) - 50} more clusters)")
        lines.append("")

    # ── Global summary
    lines.append("## Global loop label summary")
    lines.append("")
    lines.append("| label | count |")
    lines.append("|---|---|")
    from collections import Counter
    # replace bare '?' label with '(unlabeled)' so the
    # global summary table reads as English rather than showing a question
    # mark token mixed in with real label names.
    label_counter = Counter(
        (cls.get("label") or "(unlabeled)") for cls in loop_labels.values())
    for lbl, cnt in label_counter.most_common():
        lines.append(f"| `{lbl}` | {cnt} |")
    lines.append("")

    # ── Top loops by score
    lines.append("## Top loops by analytical value")
    lines.append("")
    for _k, lid, L, cls, io_sum, cs_sum in ranked:
        lines.append(f"### Loop {lid} — `{cls.get('label')}` "
                     f"(conf={cls.get('confidence')})")
        lines.append("")
        lines.append(f"- header `{L.get('header')}` → backedge "
                     f"`{L.get('backedge')}` → end `{L.get('loop_end')}`  "
                     f"(range {L.get('range_size')}B, "
                     f"{L.get('instruction_count')} insns)")
        lines.append(f"- image: `{L.get('image_path')}` "
                     f"(role=`{cls.get('image_role')}`)")
        lines.append(f"- iterations: capture={L.get('iteration_at_capture')} "
                     f"final={L.get('final_iterations')}")
        a = cls.get("activity") or {}
        lines.append(f"- activity: mem_r={a.get('mem_r')} mem_w={a.get('mem_w')} "
                     f"calls={a.get('calls')} calc={a.get('calc')} "
                     f"xor={a.get('xor')}")
        if io_sum:
            lines.append(f"- IO inside loop: total={io_sum['total']} "
                         f"groups={io_sum.get('by_group')}")
            top_apis = list(io_sum.get("by_api", {}).items())[:5]
            if top_apis:
                lines.append("  - top APIs: "
                             + ", ".join(f"`{k}`×{v}" for k, v in top_apis))
        if cs_sum:
            lines.append(f"- crypto inside loop: crypto_calls={cs_sum['crypto_calls']} "
                         f"memop_calls={cs_sum['memop_calls']} "
                         f"kinds={cs_sum.get('by_kind')}")
            top_apis = list(cs_sum.get("by_api", {}).items())[:5]
            if top_apis:
                lines.append("  - top APIs: "
                             + ", ".join(f"`{k}`×{v}" for k, v in top_apis))
        apis_in_body = (L.get("_disasm") or {}).get("apis_called") or []
        if apis_in_body:
            lines.append(f"- call targets inside body: "
                         + ", ".join(f"`{a}`" for a in apis_in_body[:8]))
        if cls.get("matches"):
            lines.append("- pattern matches (top 5):")
            for m in cls["matches"][:5]:
                lines.append(f"  - `{m['name']}` cat=`{m['category']}` "
                             f"conf={m['confidence']}")
        if cls.get("suppressed_crypto"):
            lines.append("- suppressed crypto-* (image-role gate): "
                         + ", ".join(f"`{m['name']}`"
                                     for m in cls["suppressed_crypto"]))

        listing = disasm.render_listing(L, max_lines=20)
        if listing:
            lines.append("")
            lines.append("```")
            lines.append(listing)
            lines.append("```")
        lines.append("")

    # atomic + LF-only write (see _atomic_write_text).
    _atomic_write_text(out_path, "\n".join(lines))
