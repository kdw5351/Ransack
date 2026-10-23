"""Shared adapter that flattens a Ransack analysis_report.json into
the fields the three legacy report generators (flow_report.md / report.md /
unified_report.md) historically consumed.

Single source of truth so the three report writers stay consistent.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HOOKED_RNG = ("BCryptGenRandom", "SystemFunction036", "ProcessPrng",
              "CryptGenRandom", "RtlGenRandom")
_MISSING = object()

def _safe_get(d: Any, *keys, default=None):
    # original implementation conflated "key present but
    # value is None" with "key absent" because it applied `default` only
    # on the final key, and then `return cur if cur is not None else
    # default` re-coalesced any None back to the default. Callers that
    # need to distinguish absent-vs-None (e.g. stage5 writes count being
    # genuinely 0) now get reliable None propagation: we use a sentinel
    # internally and only swap to `default` at exit when nothing was
    # found. Also guards against empty `keys` (keys[-1] would IndexError).
    if not keys:
        return d if d is not None else default
    cur = d
    for k in keys:
        if cur is None:
            return default
        if isinstance(cur, dict):
            cur = cur.get(k, _MISSING)
            if cur is _MISSING:
                return default
        else:
            return default
    return cur if cur is not None else default

def _session_id_from(trace_root: Path) -> str:
    return trace_root.name

def _family_tag(ar: dict, trace_root: Path) -> str:
    # Descriptive report label derived from the trace-folder name. (The removed
    # host-side family matching once supplied this; it is now pure grouping and
    # never drives a recovery decision.)
    name = trace_root.name
    if name.startswith("trace_"):
        name = name[len("trace_"):]
    return name.split("_")[0].lower()

def _api_count(ar: dict, api_name: str) -> int:
    return int(_safe_get(ar, "crypto_global", "by_api", api_name, default=0) or 0) + \
           int(_safe_get(ar, "io_global", "by_api", api_name, default=0) or 0)

def _infer_execution_quality(ar: dict) -> str:
    writes = _safe_get(ar, "behavior_profile", "stage5_fileops", "writes", default=0) or 0
    sym_calls = _safe_get(ar, "behavior_profile", "stage4_encrypt", "sym_calls", default=0) or 0
    asym_calls = _safe_get(ar, "behavior_profile", "stage4_encrypt", "asym_calls", default=0) or 0
    crypto_total = _safe_get(ar, "crypto_global", "total_events", default=0) or 0
    io_total = _safe_get(ar, "io_global", "total_events", default=0) or 0
    loops_total = _safe_get(ar, "behavior_profile", "stage3_loops", "total_hot_loops", default=0) or 0
    coverage_notes = _safe_get(ar, "behavior_profile", "coverage", "notes", default=[]) or []

    if writes > 0 and (sym_calls + asym_calls) > 0:
        return "encrypted_complete"
    if writes > 0 and crypto_total > 0:
        return "encrypted_partial"
    if loops_total > 0 and (sym_calls + asym_calls + writes) == 0:
        return "sample_traced_but_did_not_encrypt"
    if loops_total == 0 and crypto_total == 0 and io_total == 0:
        if "no_crypto_events" in coverage_notes and "no_io_events" in coverage_notes:
            return "pin_attach_failed"
        return "no_payload_run"
    return "indeterminate"

def _recovery_tier(passed: int, total: int, exec_quality: str) -> str:
    """Tier labels follow the paper exactly (§4.3 Recovery-Case Mapping).

    The paper defines only two binary flags as primary outputs:
        - `NO_PAYLOAD_RUN`: sample never executed an encryption pass
        - `VALIDATED`:     synthesised decryptor round-trip succeeded ≥0.5

    Everything else is described as "RC-case matched" vs. "confident no-match".
    We use:
        NO_PAYLOAD_RUN — payload/PIN issue, re-run
        RC_MATCHED    — at least one RC-01..07 passed
        INFEASIBLE    — confident no-match
    """
    if exec_quality in ("no_payload_run", "pin_attach_failed", "sample_traced_but_did_not_encrypt"):
        return "NO_PAYLOAD_RUN"
    if passed > 0:
        return "RC_MATCHED"
    return "INFEASIBLE"

# hash and RNG primitives are
# not ciphers. The exclusion is applied symmetrically in both the onHost
# report and the aggregator so sample_view.json and
# paper_aggregate.md present a consistent cipher classification.
_NOT_A_CIPHER = ("sha", "md5", "blake", "keccak", "ripemd", "crc32", "crc",
                 "rng", "random", "rtlgenrandom", "systemfunction", "genrandom")

def _is_not_cipher(s: str) -> bool:
    s = (s or "").lower()
    return any(h in s for h in _NOT_A_CIPHER)

# tier-based cipher selection.
# Symptom: deterministic cipher labels (AES-NI, AES software S-box,
# MixColumns, ChaCha20 quarter-round, ...) were systematically displaced by
# noisier XOR-stream loops carrying a single very high iteration count.
# Audit of 123 corpus samples primarily classified as XOR (stream) found 56
# (45.5%) in which a deterministic signal was simultaneously present but
# had been demoted (displaced labels: aes_sbox 98, mixcolumns 44, aes_ni 24).
# Resolution: when at least one deterministic-tier label is present, the
# winner is selected from inside the deterministic tier only. An iter<=0
# noise guard is added.
# Deterministic-tier label set, aligned 1:1 with `assets/loop_patterns.json`
# (canonical catalog). Six stale entries removed (aes_sbox, aes_round,
# rc4_prga, des_round, bignum_modmul, bignum); three canonical labels
# added (bignum_modexp, des_feistel_round, salsa20_quarter).
_DETERMINISTIC_CIPHER_LABELS = (
    "crypto.aes_ni",                # AES-NI hardware intrinsic
    "crypto.aes_software_sbox",      # AES SBOX byte transform (software)
    "crypto.aes_mixcolumns",         # AES MixColumns step
    "crypto.chacha_quarter",         # ChaCha20 quarter-round
    "crypto.salsa20_quarter",        # Salsa20 quarter-round
    "crypto.tea_round",              # TEA round
    "crypto.des_feistel_round",      # DES Feistel round
    "crypto.bignum_montgomery",      # RSA Montgomery multiplication
    "crypto.bignum_modexp",          # RSA modular exponentiation
)

def _is_deterministic_cipher(label: str) -> bool:
    return label in _DETERMINISTIC_CIPHER_LABELS

def _cipher_corroborated(label: str, ar: dict) -> bool:
    """Independent byte-gated corroboration for a loop-pattern cipher guess.

    The loop-pattern classifier is heuristic and mis-identifies (e.g. a
    captured-AES sample whose hottest crypto loop matches `bignum_modexp`, or a
    DES sample matching `xor_stream`). Only assert a cipher *confidently* when a
    separate, byte-gated signal agrees:
      - AES        <- an aeskeyfind key-schedule hit
      - RSA/bignum <- an RSA modulus / private-key blob found in the trace
      - ChaCha/Salsa <- the round's own rotation schedule
    The Bernstein-family patterns require the whole schedule -- 16, 12, 8, 7
    for ChaCha and 7, 9, 13, 18 for Salsa20 -- inside a loop doing the matching
    amount of ADD and XOR work. Those turns name the design as squarely as a key
    schedule does and no other shape in the catalogue carries them, so reaching
    this function with such a label is itself the corroboration.
    The remaining ciphers (XOR / TEA / DES) have no independent byte signature
    in this pipeline, so a loop match alone stays *unconfirmed*.
    """
    if label in ("crypto.chacha_quarter", "crypto.salsa20_quarter"):
        return True
    bs = ar.get("byte_signatures") or {}
    if not isinstance(bs, dict):
        return False
    if label in ("crypto.aes_software_sbox", "crypto.aes_ni", "crypto.aes_mixcolumns"):
        return len(bs.get("aeskeyfind_hits") or []) > 0
    if label in ("crypto.bignum_modexp", "crypto.bignum_montgomery"):
        return (int(bs.get("rsa_moduli_in_chain", 0) or 0) > 0
                or len(bs.get("cryptoapi_rsa_blob_hits") or []) > 0
                or len(bs.get("bcrypt_rsa_blob_hits") or []) > 0)
    return False

def _primary_cipher(ar: dict) -> tuple[str, float]:
    loops = (_safe_get(ar, "loops", default={}) or {})
    if not isinstance(loops, dict):
        loops = {}
    det_iter = Counter()    # Tier 1: deterministic
    det_conf = {}
    heur_iter = Counter()   # tier 2: heuristic (XOR variants)
    heur_conf = {}
    for _lid, lp in loops.items():
        if not isinstance(lp, dict):
            continue
        label = (lp.get("label") or "")
        if not label.startswith("crypto."):
            continue
        if _is_not_cipher(label):           # skip hash/RNG loop labels
            continue
        iters = int(lp.get("final_iterations") or lp.get("iteration_at_capture") or 0)
        if iters <= 0:                       # iter<=0 noise guard
            continue
        conf = float(lp.get("confidence") or 0.0)
        if _is_deterministic_cipher(label):
            det_iter[label] += iters
            det_conf[label] = max(det_conf.get(label, 0.0), conf)
        else:
            heur_iter[label] += iters
            heur_conf[label] = max(heur_conf.get(label, 0.0), conf)
    # Tier 1: deterministic-signal precedence — guarded against negligible misfires.
    # A 2-3 iteration deterministic loop (e.g. an aes_software_sbox that triggered
    # on loop_trigger_iters but is not the real cipher) must NOT outrank a far larger
    # heuristic loop. Deterministic keeps precedence UNLESS it is both tiny (below
    # _MIN_DET_ITERS) AND dwarfed by a heuristic loop. Real AES software rounds iterate
    # in the hundreds-thousands, so this only demotes artifacts. (no heuristic present
    # ⇒ heur_top=0 ⇒ deterministic still wins regardless of size, so no signal is lost.)
    _MIN_DET_ITERS = 8
    # A winning cipher loop that iterated only a handful of times is weak evidence
    # (the real encryption was barely/never captured): tag it "(low-confidence)" and
    # cap the confidence so the cipher label is not asserted as a firm call. Real
    # cipher inner-rounds iterate in the hundreds-thousands.
    _LOW_CONF_ITERS = 16

    def _finalize_cipher(winner, conf, iters):
        readable = _cipher_label_human(winner)
        conf = round(conf, 2)
        # Corroboration gate: a loop-pattern cipher is asserted confidently only
        # when an independent byte-gated signal agrees (aeskeyfind for AES, an RSA
        # blob/modulus for bignum). Without it the loop classifier's guess is an
        # explicitly heuristic hint — cap hard and tag, since it is often wrong
        # (captured-AES -> bignum_modexp, DES -> xor_stream, ChaCha20 -> aes_*).
        if not _cipher_corroborated(winner, ar):
            return f"{readable} (heuristic, unconfirmed)", min(conf, 0.35)
        if iters < _LOW_CONF_ITERS:
            return f"{readable} (low-confidence)", min(conf, 0.35)
        return readable, conf

    det_top  = max(det_iter.values()) if det_iter else 0
    heur_top = max(heur_iter.values()) if heur_iter else 0
    if det_iter and (det_top >= _MIN_DET_ITERS or det_top >= heur_top):
        # cross-PC determinism — sorted (-iter, label) tie-break.
        winner = sorted(det_iter.items(), key=lambda x: (-x[1], x[0]))[0][0]
        # 0.5 default unreachable — winner in det_iter ⇒ winner in det_conf.
        return _finalize_cipher(winner, det_conf.get(winner, 0.5), det_iter[winner])
    # tier 2 fallback: heuristic
    if heur_iter:
        winner = sorted(heur_iter.items(), key=lambda x: (-x[1], x[0]))[0][0]
        return _finalize_cipher(winner, heur_conf.get(winner, 0.5), heur_iter[winner])
    # Fallback: the captured keys, named by the length rules (guard applied).
    # Both inventories are consulted. `wrapped_session_keys` holds the session
    # keys taken in the clear at a wrap input, which are kept out of `sym_keys`
    # so they cannot feed the weak-RNG and hardcoded-key predicates -- but a run
    # whose only key material is there still has a named cipher to report.
    for bucket in ("sym_keys", "wrapped_session_keys"):
        for sk in _safe_get(ar, "crypto_global", bucket, default=[]) or []:
            algo = (sk.get("algorithm") if isinstance(sk, dict) else None) or ""
            if algo and not _is_not_cipher(algo):
                return f"{algo.upper()} (key-length inferred)", 0.4
    return "no cipher identified", 0.0

def _cipher_label_human(label: str) -> str:
    # Stale rendering-table entries removed: labels the classifier never
    # produces (no counterpart in `assets/loop_patterns.json`).
    table = {
        "crypto.aes_mixcolumns": "AES (MixColumns observed)",
        "crypto.aes_software_sbox": "AES (S-box, software)",
        "crypto.aes_ni": "AES NI",
        "crypto.bignum_montgomery": "BIGNUM MONTGOMERY",
        "crypto.bignum_modexp": "BIGNUM ModExp",
        "crypto.des_feistel_round": "DES (Feistel round)",
        "crypto.salsa20_quarter": "Salsa20 (quarter-round)",
        "crypto.chacha_quarter": "ChaCha20 (quarter-round)",
        "crypto.tea_round": "TEA (round)",
        "crypto.xor_chain_double": "XOR-chain (double)",
        "crypto.xor_stream": "XOR (stream)",
        "crypto.xor_rotate": "XOR (rotate)",
        # Removed: des_round, sha2_compress, rc4_prga — not present in
        # `assets/loop_patterns.json` (mirror clean-up in the report pipeline).
    }
    return table.get(label, label.replace("crypto.", "").replace("_", " ").upper())

def _key_chain_depth(ar: dict) -> int:
    return int(_safe_get(ar, "chain", "stats", "max_chain_depth", default=0) or 0)

def _extract_recovery_details(passed_case: dict, ar: dict) -> list[tuple[str, str]]:
    """Return a list of (label, value) pairs for renderable display.
    Each RC paths to a custom block, drawing from the specific evidence
    fields its `evidence_required` conjunction consumes (paper §III-C
    Table 1). 
    """
    case_id = (passed_case.get("case_id") or "").upper()
    cs = ar.get("crypto_global") or {}
    by_api = (cs.get("by_api") or {})
    residue = ar.get("residue") or {}

    if case_id == "RC-01":
        export_count = by_api.get("BCryptExportKey", 0) + by_api.get("CryptExportKey", 0)
        for blob in cs.get("asym_blobs") or []:
            fmt = blob.get("format") or blob.get("magic") or "?"
            hexstr = blob.get("hex") or ""
            out_len = blob.get("out_len") or "?"
            is_private = blob.get("is_private")
            items = [
                ("Export API calls", str(export_count)),
                ("Blob format", f"`{fmt}`"),
                ("Blob length", f"{out_len} B"),
                ("Is private?", "yes" if is_private else "no"),
            ]
            if hexstr:
                items.append(("Blob hex (head)", f"`{hexstr[:64]}…`"))
            return items
        return [("Status", "(blob present but no detail extracted)")]

    if case_id == "RC-02":
        keygen_apis = {k: by_api.get(k, 0) for k in (
            "BCryptGenerateKeyPair", "CryptGenKey",
            "BCryptFinalizeKeyPair", "RSA_generate_key_ex"
        ) if by_api.get(k, 0) > 0}
        rcl = residue.get("residue_class") or residue.get("class")
        matches = residue.get("total_matches", 0)
        tags = residue.get("unique_tags") or residue.get("unique_tags_with_hit") or []
        promotion = residue.get("byte_sig_promotion") or {}
        items = [
            ("RSA keygen APIs", ", ".join(f"`{k}`={v}" for k, v in keygen_apis.items()) or "(none observed)"),
            ("Residue class", f"`{rcl}` (threshold = HIGH)"),
            ("Residue matches", str(matches)),
            ("Unique tags", ", ".join(tags[:6]) if isinstance(tags, list) else "(none)"),
        ]
        if matches == 0 and promotion.get("to") and promotion.get("from") != promotion.get("to"):
            items.append((
                "Promotion warning",
                f"real match count = 0 but residue_class promoted "
                f"`{promotion.get('from')}` → `{promotion.get('to')}` via "
                f"`{', '.join(promotion.get('reasons') or [])}`. "
                "**This may be a false positive — `aeskeyfind` matches AES "
                "round-key schedules, not RSA keypairs (paper §III-C RC-02 = "
                "RSA-keypair in heap). Audit required.**"
            ))
        return items

    if case_id == "RC-03":
        cryptoapi_apis = {k: by_api.get(k, 0) for k in (
            "CryptGenKey", "CryptAcquireContext", "CryptAcquireContextA",
            "CryptAcquireContextW", "CryptReleaseContext"
        ) if by_api.get(k, 0) > 0}
        rcl = residue.get("residue_class") or residue.get("class")
        matches = residue.get("total_matches", 0)
        tags = residue.get("unique_tags") or residue.get("unique_tags_with_hit") or []
        promotion = residue.get("byte_sig_promotion") or {}
        items = [
            ("CryptoAPI keygen APIs", ", ".join(f"`{k}`={v}" for k, v in cryptoapi_apis.items()) or "(none observed)"),
            ("Residue class", f"`{rcl}` (threshold = MID, RC-03 = wanakiwi 128B window)"),
            ("Residue matches", str(matches)),
            ("Unique tags", ", ".join(tags[:6]) if isinstance(tags, list) else "(none)"),
            ("Decryption technique", "Slide 128 B window over heap, accept candidate iff N % candidate == 0 against on-disk public modulus"),
        ]
        if matches == 0 and promotion.get("to") and promotion.get("from") != promotion.get("to"):
            items.append((
                "Promotion warning",
                f"real match count = 0 but residue_class promoted "
                f"`{promotion.get('from')}` → `{promotion.get('to')}` via "
                f"`{', '.join(promotion.get('reasons') or [])}`. "
                "**Audit required: paper §III-C RC-03 is wanakiwi RSA-prime scan; "
                "AES-key promotion may not be valid evidence here.**"
            ))
        return items

    if case_id == "RC-06":
        artifacts = []
        for e in passed_case.get("evidence") or []:
            obs = str(e.get("observed") or "")
            if "decisive artifact" in obs.lower():
                artifacts.append(obs)
        bs = ar.get("byte_signatures") or {}
        aes_keys = bs.get("aeskeyfind_keys") or sorted(
            {h.get("key_hex") for h in (bs.get("aeskeyfind_hits") or []) if h.get("key_hex")})
        items = [
            ("Decisive artifacts", "; ".join(artifacts) or "(captured on-trace)"),
            ("Residue class", f"`{residue.get('residue_class') or residue.get('class')}`"),
            ("Residue matches", str(residue.get("total_matches", 0))),
        ]
        if aes_keys:
            shown = "\n".join(f"  - `{k}`" for k in aes_keys[:8])
            items.append(("AES key schedules recovered", f"{len(aes_keys)} distinct\n{shown}"))
            items.append(("How to use them", "Each is a candidate AES key located by the "
                          "key-schedule self-consistency scan. Trial-decrypt the sealed files "
                          "with it; a wrong key leaves ciphertext entropy unchanged, so a real "
                          "one is recognisable without a reference copy."))
        items.append(("Recovery basis", "A captured cipher constant / key-residue signature / family marker pins the cipher/family -- a partial-recovery path (feasibility), not a guaranteed full-key dump"))
        return items

    if case_id == "RC-04":
        keys = cs.get("sym_keys") or []
        captured = [k for k in keys if k.get("hex")]
        if captured:
            k0 = captured[0]
            hexstr = k0["hex"]
            kl = k0.get("len") or "?"
            algo = k0.get("algorithm") or "?"
            src = k0.get("source") or "?"
            items = [
                ("Key bytes", f"`{hexstr}`"),
                ("Algorithm", f"{algo}, {kl} B"),
                ("Source", f"`{src}`"),
            ]
            prov = k0.get("snapshot_provenance") or {}
            if prov:
                items.append((
                    "Provenance",
                    f"`{prov.get('snapshot_file')}` offset "
                    f"{prov.get('offset_in_file', 0)} @ buf "
                    f"0x{prov.get('buf_address')}"
                ))
            items.append(("Total sym_keys", str(len(keys))))
            return items
        if keys:
            k0 = keys[0]
            return [
                ("Algorithm", f"{k0.get('algorithm', '?')}, {k0.get('len', '?')} B"),
                ("Key bytes", "`NOT_CAPTURED` (buffer below PinTool capture cap)"),
                ("Source", f"`{k0.get('source', '?')}`"),
                ("Total sym_keys", str(len(keys))),
            ]
        return [("Status", "(hardcoded indicator present, no key extracted)")]

    if case_id == "RC-05":
        rng_apis = {k: v for k, v in (cs.get("by_api") or {}).items()
                    if k in ("SystemFunction036", "RtlGenRandom",
                             "BCryptGenRandom", "CryptGenRandom",
                             "ProcessPrng")}
        return [
            ("RNG calls (total)", str(sum(rng_apis.values()))),
            ("RNG APIs", ", ".join(f"`{k}`={v}" for k, v in list(rng_apis.items())[:4]) or "(none)"),
            ("Chain depth", str(_key_chain_depth(ar))),
        ]

    if case_id == "RC-07":
        keys = cs.get("sym_keys") or []
        # RC-07 also fires on key material captured plaintext at the RSA-wrap input,
        # which is deliberately kept out of `sym_keys` (see crypto_summary.
        # harvest_wrapped_session_keys). Surface it here too, or an operator reading a
        # fired RC-07 finds an empty value block.
        wrapped = cs.get("wrapped_session_keys") or []
        if wrapped and not keys:
            wcap = [k for k in wrapped if k.get("hex")]
            rows = [
                ("Source", "captured plaintext at the RSA-wrap input (PayBreak class)"),
                ("Total wrapped session keys",
                 str(cs.get("wrapped_session_keys_count") or len(wrapped))),
                ("Keys with captured bytes", str(len(wcap))),
            ]
            if wcap:
                rows.append(("Captured key samples",
                             "\n" + "\n".join(f"  - `{k['hex']}`" for k in wcap[:5])))
                ivs = [k.get("iv_hex") for k in wcap[:3] if k.get("iv_hex")]
                if ivs:
                    rows.append(("Trailing bytes (IV / nonce)",
                                 ", ".join(f"`{v}`" for v in ivs)))
            rows.append(("decryption_essentials.json", "present"))
            return rows
        captured = [k for k in keys if k.get("hex")]
        # Cipher parameters recovered alongside the key (chaining mode / IV)
        # let the operator move from "key in hand" to an actual decryptor.
        mode = cs.get("cipher_mode")
        ivs = cs.get("iv_candidates") or []
        param_rows = []
        if mode:
            param_rows.append(("Chaining mode (recovered)", f"`{mode}`"))
        if ivs:
            iv_show = ", ".join(f"`{v}`" for v in ivs[:3])
            extra = cs.get("iv_total") or len(ivs)
            param_rows.append(("IV candidate(s)", f"{iv_show} (total {extra})"))
        if captured:
            samples = "\n".join(f"  - `{k['hex']}`" for k in captured[:5])
            return [
                ("Total sym_keys", str(len(keys))),
                ("Keys with captured bytes", str(len(captured))),
                ("Captured key samples", "\n" + samples),
                *param_rows,
                ("decryption_essentials.json", "present"),
            ]
        lens = [str(k.get("len") or "?") for k in keys[:3]]
        algos = [k.get("algorithm") or "?" for k in keys[:3]]
        return [
            ("Total sym_keys", str(len(keys))),
            ("Captured bytes", "0 (PinTool capture cap)"),
            ("Length-only entries", ", ".join(f"{l}B" for l in lens)),
            ("Algorithms (inferred)", ", ".join(algos)),
            ("decryption_essentials.json", "present"),
        ]

    return [("Status", "—")]

def _extract_recovery_value(passed_case: dict, ar: dict) -> str:
    """Backward-compat single-line summary.
    Builds a comma-joined "label: value" string from _extract_recovery_details.
    Kept on the record for sample_view.json consumers that scan a flat string.
    """
    items = _extract_recovery_details(passed_case, ar)
    return "; ".join(
        f"{label}={value}".replace("\n  - ", "[").rstrip("[") + ("]" if "\n  - " in value else "")
        for label, value in items
    )

def _strict_passed_cases(ar: dict) -> list[dict]:
    out = []
    for c in (_safe_get(ar, "recovery_cases", "passed", default=[]) or []):
        if not isinstance(c, dict):
            continue
        evidence_summary = [
            {"primitive": e.get("primitive"), "observed": e.get("observed")}
            for e in (c.get("evidence") or [])
            if isinstance(e, dict) and e.get("ok")
        ]
        details = _extract_recovery_details(c, ar)
        out.append({
            "case_id": c.get("case_id") or c.get("id"),
            "name": c.get("name"),
            "strategy": c.get("strategy"),
            "confidence": c.get("confidence_when_met"),
            "recovery_value": _extract_recovery_value(c, ar),
            "recovery_details": [{"label": l, "value": v} for l, v in details],
            "evidence_matched": evidence_summary,
        })
    return out

def _failed_cases(ar: dict) -> list[dict]:
    out = []
    for c in (_safe_get(ar, "recovery_cases", "failed", default=[]) or []):
        if not isinstance(c, dict):
            continue
        blocking = []
        for ev in (c.get("blocking_evidence") or []):
            if isinstance(ev, dict):
                blocking.append({
                    "primitive": ev.get("primitive"),
                    "observed": ev.get("observed"),
                    "support": ev.get("support"),
                })
        out.append({
            "case_id": c.get("case_id") or c.get("id"),
            "name": c.get("name"),
            "strategy": c.get("strategy"),
            "confidence": c.get("confidence_when_met"),
            "blocking": blocking,
        })
    return out

def _loop_category_breakdown(ar: dict) -> tuple[dict, dict]:
    """Returns (by_category, by_label) where each value is {clusters: int, iters: int}."""
    loops = _safe_get(ar, "loops", default={}) or {}
    cat_clusters = defaultdict(set)
    cat_iters = defaultdict(int)
    label_clusters = defaultdict(set)
    label_iters = defaultdict(int)
    label_to_cat = {}

    for lid, lp in loops.items():
        if not isinstance(lp, dict):
            continue
        cat = lp.get("category") or "other"
        label = lp.get("label") or "unknown.utility"
        cluster_id = lp.get("cluster_id") or lid
        # iter<=0 noise guard; coerce missing iteration to 0 (not 1).
        iters = int(lp.get("final_iterations") or lp.get("iteration_at_capture") or 0)
        if iters <= 0:
            continue
        cat_clusters[cat].add(cluster_id)
        cat_iters[cat] += iters
        label_clusters[label].add(cluster_id)
        label_iters[label] += iters
        label_to_cat[label] = cat

    by_cat = {c: {"clusters": len(cat_clusters[c]), "iters": cat_iters[c]} for c in cat_clusters}
    by_label = {
        lab: {"clusters": len(label_clusters[lab]),
              "iters": label_iters[lab],
              "category": label_to_cat[lab]}
        for lab in label_clusters
    }
    return by_cat, by_label

CATEGORY_DESCRIPTIONS = {
    "memory_string_ops": "Memory/string helpers (memcpy_dword, memcmp_dword — Windows runtime activity)",
    "other": "Uncategorized",
    "string_processing": "String parsing (kill-list, target extension, ransom note template)",
    "control_flow": "Control flow dispatch (indirect call, virtual table, jump table)",
    "memory_ops": "Memory init/allocation (memset, RtlAllocateHeap walker)",
    "memory_copy": "Memory copy / move primitives (memcpy, RtlMoveMemory)",
    "memory_pack": "Memory pack/unpack & bit-shuffle (packer stub, struct serialisation)",
    "anti_analysis": "Anti-debug / anti-VM loops (sleep, timing checks, IsDebuggerPresent)",
    "crypto": "Crypto-labelled loops (AES round/sbox, ChaCha quarter, XOR stream/chain, TEA round, hash compress)",
    "crypto.encryption": "Encryption loops (AES round, ChaCha quarter, hash compress — core ransomware activity)",
    "degenerate": "Single-instruction or empty body (NOP probe)",
    "filesystem_io": "Filesystem read/write pair (encrypted file output)",
    "file_io": "Filesystem read/write pair (encrypted file output)",
    "fs": "Filesystem read/write pair (encrypted file output)",
    "counters": "Simple counter loops (loop counter increment)",
    "fallback": "Fallback / unclassified loops (no rule fired — likely benign Windows runtime utility)",
    "string": "String operations (strcmp, case_convert, tokeniser)",
    "hash": "Hash compression rounds (SHA-2, MD5 round body)",
    "kdf": "Key derivation primitives (PBKDF2 iteration, HKDF expand)",
    "rng": "RNG / entropy mixing loops",
    "io_loop": "I/O dispatch loops (per-file walk, recursive directory traversal)",
    # Canonical loop_patterns.json categories (kept in sync with assets/loop_patterns.json)
    "anti_forensic": "Anti-forensic loops (secure-wipe, shadow-copy deletion, log clearing)",
    "encoding": "Encoding / transcoding loops (base64, hex, URL, custom alphabet)",
    "memory_compare": "Memory comparison loops (memcmp-style scan for a match)",
    "memory_init": "Memory initialisation / fill loops (memset-style)",
    "memory_process": "Bulk buffer-processing loops (transform over a memory region)",
    "memory_scan": "Memory-scanning loops (search a region for a pattern or marker)",
    "stack_op": "Stack-manipulation loops (push/pop runs, frame setup)",
    "crypto_or_mask_mix": "Ambiguous: XOR/mask arithmetic that may be a cipher core or bit-masking / obfuscation",
    "crypto_or_pointer_mix": "Ambiguous: cipher-like arithmetic interleaved with pointer walking (needs disambiguation)",
}

def _scored_loops(ar: dict, n=10) -> list[dict]:
    loops = _safe_get(ar, "loops", default={}) or {}
    scored = []
    for lid, lp in loops.items():
        if not isinstance(lp, dict):
            continue
        # iter<=0 guard: prevents 1–2-point noise loops from entering the top-10 list.
        iters = int(lp.get("final_iterations") or lp.get("iteration_at_capture") or 0)
        if iters <= 0:
            continue
        crypto_calls = int(_safe_get(lp, "crypto_summary", "crypto_calls", default=0) or 0)
        conf = float(lp.get("confidence") or 0.0)
        label = lp.get("label") or ""
        score = iters * (1 + crypto_calls * 5) * (1 + conf * 2)
        if label.startswith("crypto."):
            score *= 2
        scored.append({
            "score": int(score),
            "label": label,
            "iters": iters,
            "header": f"0x{lp.get('header')}" if lp.get("header") else None,
            "cluster_id": lp.get("cluster_id"),
            "image_module": lp.get("image_module"),
        })
    scored.sort(key=lambda x: -x["score"])
    return scored[:n]

def _load_dll_names_from_images(trace_root: Path) -> list[str]:
    """When `analysis_report.loaded_dlls.list` is empty, recover DLL names from
    the raw `images_*.jsonl` streams the pintool emitted."""
    names: list[str] = []
    seen: set[str] = set()
    candidates: list[Path] = []
    for sub in (trace_root, *(p for p in trace_root.iterdir() if p.is_dir() and p.name.startswith("proc_"))):
        candidates.extend(sorted(sub.glob("images_*.jsonl")))
    for jl in candidates:
        try:
            with jl.open("r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    path = rec.get("path") or rec.get("image_path")
                    if not path:
                        continue
                    base = path.replace("/", "\\").split("\\")[-1]
                    if not base:
                        continue
                    bl = base.lower()
                    if bl in seen:
                        continue
                    seen.add(bl)
                    names.append(base)
        except Exception:
            continue
    return names

def _ransomflow_done(trace_root: Path) -> dict | None:
    """The `ransomflow_done.json` sidecar always has runtime + peak WSS even
    when analysis_report.runtime is null. ONLY emitted on clean PIN shutdown
    — crash / abort traces will not have it (see `_runtime_from_mtimes`)."""
    candidates = [trace_root / "ransomflow_done.json"]
    for proc in sorted(trace_root.glob("proc_*")):
        candidates.append(proc / "ransomflow_done.json")
    for p in candidates:
        if p.exists():
            try:
                with p.open("r", encoding="utf-8") as fh:
                    return json.load(fh)
            except Exception:
                continue
    return None

def _runtime_from_mtimes(trace_root: Path) -> tuple[float | None, str]:
    """Fallback when ransomflow_done.json is missing — PIN crashed before the
    clean-shutdown write. Estimates runtime from the spread of mtimes across
    the PIN-emitted artifacts (proc_info.json, loop_*.{bin,json},
    *_events_*.jsonl, *_snapshots_*.jsonl).

    Returns (seconds, source) where source describes which method produced the
    value (\"clean\", \"mtime\", or \"none\")."""
    pin_glob_patterns = (
        "proc_*/proc_info.json",
        "proc_*/loop_*.json",
        "proc_*/loop_*.bin",
        "proc_*/crypto_events_*.jsonl",
        "proc_*/io_events_*.jsonl",
        "proc_*/key_residue_snapshots_*.jsonl",
        "proc_*/images_*.jsonl",
        "proc_*/loop_events.jsonl",
    )
    times: list[float] = []
    for pat in pin_glob_patterns:
        for p in trace_root.glob(pat):
            try:
                times.append(p.stat().st_mtime)
            except OSError:
                continue
    if len(times) < 2:
        return None, "none"
    span = max(times) - min(times)
    if span <= 0:
        return None, "none"
    return round(span, 3), "mtime"

def _pin_attach_failed(trace_root: Path) -> bool:
    """Whether PIN bailed before the analysis routine could capture anything.

    Decision is deterministic and made on TWO observations of the on-disk
    trace, not on stderr/stdout text alone:

      (a) Did PIN ever produce a populated `proc_<pid>/` artefact? When the
          auto-bitness driver retries with the opposite bitness (see
          onVM/run.ps1), the FIRST attempt may emit an error to
          pin_stderr_64bit.log / pin_stdout_64bit.log (typical: "Failure to
          map DLL ... System error 216" for an X-bit Pin attaching to a
          (X^1)-bit sample), and the SECOND attempt then succeeds and writes
          a populated proc_<pid>/ . The first-attempt error is part of the
          documented fallback contract, not an attach failure.
          So: if any proc_<pid>/ directory contains non-empty
          ransomflow_done.json OR any non-empty crypto_events_*.jsonl OR any
          non-empty io_events_*.jsonl, attach succeeded -> return False.
      (b) Otherwise: fall through to the stderr/stdout signals (the
          historical behaviour).

    Rationale: paper §IV-A requires execution_quality to reflect whether
    instrumentation succeeded, which is directly observable by the presence
    of trace artefacts written by the PinTool's PIN_AddFiniFunction /
    chunked-log writer paths. The stderr/stdout heuristic stays as a safety
    net for the case where NO proc_<pid>/ artefacts exist at all (PIN truly
    never reached the analysis routine)."""
    # Step (a): deterministic check for any populated proc_<pid>/ artefact.
    for proc_dir in trace_root.glob("proc_*"):
        if not proc_dir.is_dir():
            continue
        # ransomflow_done.json is written by PIN_AddFiniFunction (OnFini),
        # so its presence with non-zero size is conclusive proof the Pin
        # process reached graceful shutdown.
        done = proc_dir / "ransomflow_done.json"
        try:
            if done.is_file() and done.stat().st_size > 0:
                return False
        except OSError:
            pass
        # Any non-empty chunked log file also proves PinTool's
        # InitializeOutputFiles() + InitChunkedLog() succeeded and at least
        # one event row was written by the instrumentation path.
        for pattern in ("crypto_events_*.jsonl",
                        "io_events_*.jsonl",
                        "images_*.jsonl"):
            for chunk in proc_dir.glob(pattern):
                try:
                    if chunk.stat().st_size > 0:
                        return False
                except OSError:
                    continue

    # Step (b): historical stderr/stdout signal-based detection (no
    # populated proc_<pid>/ found above).
    for p in trace_root.glob("pin_stderr_*.log"):
        try:
            if p.stat().st_size > 0:
                return True
        except OSError:
            continue
    for p in trace_root.glob("pin_stdout_*.log"):
        try:
            with p.open("r", encoding="utf-8", errors="ignore") as fh:
                head = fh.read(512)
            # original `A or B and C` relied on Python's
            # `and` > `or` precedence; while functionally equivalent the
            # intent was unclear. Make grouping explicit.
            head_lower = head.lower()
            if ("Failure to map DLL" in head) or (
                "ransomflow" in head_lower and "fail" in head_lower
            ):
                return True
        except OSError:
            continue
    return False

def _heuristic_role(name: str) -> str:
    ln = name.lower()
    if "crypt" in ln or ln in ("rsaenh.dll", "bcrypt.dll", "ncrypt.dll", "bcryptprimitives.dll"):
        return "crypto.provider" if ("enh" in ln or "bcrypt" in ln) else "crypto.primitive"
    if ln in ("ole32.dll", "oleaut32.dll", "combase.dll"):
        return "com"
    if ln in ("kernel32.dll", "kernelbase.dll", "ntdll.dll", "advapi32.dll",
              "win32u.dll", "rpcrt4.dll", "sechost.dll"):
        return "system.api_core"
    if ln in ("user32.dll", "gdi32.dll", "shell32.dll", "comctl32.dll",
              "gdi32full.dll", "shcore.dll", "uxtheme.dll", "imm32.dll"):
        return "gui"
    if ln.startswith("msvc") or ln.startswith("vcruntime"):
        return "runtime.cpp"
    if "crt" in ln or ln in ("ucrtbase.dll", "ucrtbased.dll"):
        return "runtime.crt"
    if ln.endswith(".pyd") or "python" in ln:
        return "runtime.python"
    if "mscoree" in ln or "clr" in ln or "fusion" in ln:
        return "runtime.dotnet"
    if ln in ("ws2_32.dll", "wininet.dll", "winhttp.dll", "iphlpapi.dll", "dnsapi.dll"):
        return "network"
    if "wmi" in ln:
        return "wmi"
    if ln in ("psapi.dll", "version.dll", "winmm.dll"):
        return "system.misc"
    if ln.endswith(".nls") or ln.endswith(".dat"):
        return "system.misc"
    return "library.unknown"

def _loaded_dll_names(ar: dict, trace_root: Path | None = None) -> list:
    """The loaded-DLL basenames for a trace, taken from analysis_report or, if
    that list is empty, recovered from the captured images."""
    dlls = _safe_get(ar, "loaded_dlls", "list", default=[]) or []
    names: list[str] = []
    if isinstance(dlls, list) and dlls:
        if isinstance(dlls[0], str):
            names = list(dlls)
        else:
            for d in dlls:
                if isinstance(d, dict):
                    bn = d.get("base_name") or d.get("name")
                    if bn:
                        names.append(bn)
    if not names and trace_root is not None:
        names = _load_dll_names_from_images(trace_root)
    return names


def _dll_role_breakdown(ar: dict, dll_roles_catalogue: dict | None,
                        trace_root: Path | None = None) -> dict:
    names = _loaded_dll_names(ar, trace_root)

    roles = defaultdict(int)
    rmap = None
    if dll_roles_catalogue:
        rmap = {k.lower(): v for k, v in dll_roles_catalogue.items()
                if not k.startswith("_comment")}
    for n in names:
        role = None
        if rmap is not None:
            role = rmap.get(n.lower())
        if not role:
            role = _heuristic_role(n)
        if role == "instrumentation":
            continue
        roles[role] += 1
    return dict(roles)

def _evidence_tree(ar: dict) -> dict:
    """Build an evidence-grounded view of what the trace ACTUALLY captured,
    so Stage 10 can render a per-sample tree instead of a fixed template.

    Returns a dict shaped for the Mermaid renderer:
        {
          "rng_apis":    {api: calls}        # only APIs with calls > 0
          "keygen_apis": {api: calls}
          "kdf_apis":    {api: calls}
          "hash_apis":   {api: calls}
          "key_import":  {api: calls}
          "key_export":  {api: calls}
          "sym_sinks":   {api: calls}
          "asym_sinks":  {api: calls}
          "by_kind":     {kind: events}      # rand/keygen/kdf/sym_enc/asym_enc/hash/...
          "chain_src_apis": {api: tag_count} # actual src nodes in chain.nodes
          "chain_embedded_root_apis": {api: tag_count}
          "loops_categories": [{cat, label, clusters, iters, style}, ...]
          "files": {op: count}
          "inline_cipher": "label" or None
        }
    """
    out = {
        "rng_apis": {}, "keygen_apis": {}, "kdf_apis": {}, "hash_apis": {},
        "key_import": {}, "key_export": {},
        "sym_sinks": {}, "asym_sinks": {},
        "by_kind": {},
        "chain_src_apis": defaultdict(int),
        "chain_embedded_root_apis": defaultdict(int),
        "loops_categories": [],
        "files": {},
        "inline_cipher": None,
    }
    by_api = _safe_get(ar, "crypto_global", "by_api", default={}) or {}
    by_kind = _safe_get(ar, "crypto_global", "by_kind", default={}) or {}
    out["by_kind"] = {k: v for k, v in by_kind.items() if v and k != "?"}

    stage2 = _safe_get(ar, "behavior_profile", "stage2_keygen", default={}) or {}
    stage4 = _safe_get(ar, "behavior_profile", "stage4_encrypt", default={}) or {}
    for api in stage2.get("rng_apis", []) or []:
        if by_api.get(api, 0) > 0:
            out["rng_apis"][api] = by_api[api]
    for api in stage2.get("keygen_apis", []) or []:
        if by_api.get(api, 0) > 0:
            out["keygen_apis"][api] = by_api[api]
    for api in stage2.get("kdf_apis", []) or []:
        if by_api.get(api, 0) > 0:
            out["kdf_apis"][api] = by_api[api]
    for api in stage4.get("sym_apis", []) or []:
        if by_api.get(api, 0) > 0:
            out["sym_sinks"][api] = by_api[api]
    for api in stage4.get("asym_apis", []) or []:
        if by_api.get(api, 0) > 0:
            out["asym_sinks"][api] = by_api[api]

    for api, ct in by_api.items():
        if not ct or api == "?":
            continue
        if api in out["rng_apis"] or api in out["keygen_apis"] or api in out["kdf_apis"]:
            continue
        if api in out["sym_sinks"] or api in out["asym_sinks"]:
            continue
        if "Hash" in api or "Sha" in api or "Md5" in api:
            out["hash_apis"][api] = ct
        elif "Import" in api or "ImportKey" in api:
            out["key_import"][api] = ct
        elif "Export" in api:
            out["key_export"][api] = ct
        elif "Encrypt" in api and "Asym" not in api:
            out["sym_sinks"][api] = ct
        elif "Acquire" in api or "GenRandom" in api or api in ("SystemFunction036", "ProcessPrng"):
            out["rng_apis"][api] = ct

    nodes = _safe_get(ar, "chain", "nodes", default=[]) or []
    for n in nodes:
        if not isinstance(n, dict):
            continue
        born_by = n.get("born_by") or []
        if not born_by:
            continue
        api = born_by[0] if isinstance(born_by, list) and born_by else None
        if not api:
            continue
        if n.get("is_src"):
            out["chain_src_apis"][api] += 1
        if n.get("is_embedded_root"):
            out["chain_embedded_root_apis"][api] += 1
    out["chain_src_apis"] = dict(out["chain_src_apis"])
    out["chain_embedded_root_apis"] = dict(out["chain_embedded_root_apis"])

    by_cat, _ = _loop_category_breakdown(ar)
    for cat, info in sorted(by_cat.items(), key=lambda x: -x[1]["iters"]):
        if info["clusters"] <= 0:
            continue
        if cat.startswith("crypto"):
            style = "cryptol"
        elif "anti" in cat:
            style = "antil"
        elif cat in ("filesystem_io", "file_io", "fs"):
            style = "file"
        else:
            style = "other"
        out["loops_categories"].append({
            "cat": cat, "clusters": info["clusters"],
            "iters": info["iters"], "style": style,
        })

    # inline_cipher now applies the same deterministic-tier + iter<=0
    # policy used by _primary_cipher. Previously the two paths could diverge:
    # a sample with an AES-NI signal but no XOR-loop iterations was being
    # misclassified as XOR (stream).
    loops = _safe_get(ar, "loops", default={}) or {}
    det_iter = Counter()
    heur_iter = Counter()
    for lp in loops.values():
        if not isinstance(lp, dict):
            continue
        label = lp.get("label") or ""
        if not label.startswith("crypto."):
            continue
        if _is_not_cipher(label):
            continue
        iters = int(lp.get("final_iterations") or lp.get("iteration_at_capture") or 0)
        if iters <= 0:
            continue
        if _is_deterministic_cipher(label):
            det_iter[label] += iters
        else:
            heur_iter[label] += iters
    # cross-PC determinism — sorted tie-break.
    if det_iter:
        out["inline_cipher"] = sorted(det_iter.items(), key=lambda x: (-x[1], x[0]))[0][0]
    elif heur_iter:
        out["inline_cipher"] = sorted(heur_iter.items(), key=lambda x: (-x[1], x[0]))[0][0]

    fs = _safe_get(ar, "behavior_profile", "stage5_fileops", default={}) or {}
    for op in ("reads", "writes", "moves", "deletes"):
        if fs.get(op, 0):
            out["files"][op] = fs[op]
    return out

# --------------------------------------------------------------------------
# behavioral evidence + evasion detector (mirror of
# report/schema.py). See that twin for full rationale.
# --------------------------------------------------------------------------

_BEHAVIORAL_APIS = {
    "Injection": (
        # Strict markers — cross-process control APIs only.
        # Excluded: NtMapViewOfSection, NtAllocateVirtualMemory (legitimate).
        "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx",
        "WriteProcessMemory", "NtWriteVirtualMemory",
        "QueueUserAPC", "NtQueueApcThread", "SetWindowsHookEx",
        "VirtualAllocEx", "RtlCreateUserThread",
        "SetThreadContext", "NtSetContextThread",
    ),
    "FileRename": (
        "MoveFile", "MoveFileA", "MoveFileW",
        "MoveFileEx", "MoveFileExA", "MoveFileExW",
        "NtSetInformationFile",
    ),
    "FileDelete": (
        "DeleteFile", "DeleteFileA", "DeleteFileW", "NtDeleteFile",
        "SHFileOperation", "SHFileOperationA", "SHFileOperationW",
    ),
    "C2_Network": (
        "InternetOpen", "InternetConnect", "WinHttpOpen", "WinHttpConnect",
        "HttpSendRequest", "send", "recv", "connect", "WSAConnect",
        "DnsQuery", "DnsQueryA", "DnsQueryW", "getaddrinfo", "gethostbyname",
    ),
    "AntiAnalysis": (
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "NtSetInformationThread",
        "OutputDebugString", "FindWindow", "FindWindowA", "FindWindowW",
        "GetTickCount", "QueryPerformanceCounter", "NtDelayExecution",
    ),
}

def _extract_behavioral_evidence(ar: dict) -> dict:
    cg_api = (ar.get("crypto_global") or {}).get("by_api") or {}
    io_api = (ar.get("io_global") or {}).get("by_api") or {}
    combined = Counter(cg_api) + Counter(io_api)
    out = {}
    for cat, apis in _BEHAVIORAL_APIS.items():
        hits = {a: combined.get(a, 0) for a in apis if combined.get(a, 0) > 0}
        if hits:
            total = sum(hits.values())
            top = sorted(hits.items(), key=lambda kv: -kv[1])[:5]
            out[cat] = {
                "total": total,
                "api_count": len(hits),
                "top_apis": [{"api": a, "count": c} for a, c in top],
            }
    out["_pintool_gaps"] = []
    if "C2_Network" not in out:
        out["_pintool_gaps"].append("C2_Network")
    if "AntiAnalysis" not in out:
        out["_pintool_gaps"].append("AntiAnalysis")
    return out

def _detect_evasion_suspected(ar: dict) -> dict:
    cg = ar.get("crypto_global") or {}
    by_kind = cg.get("by_kind") or {}
    by_api = cg.get("by_api") or {}
    io_api = (ar.get("io_global") or {}).get("by_api") or {}
    encrypt_calls = by_kind.get("sym_enc", 0) + by_kind.get("asym_enc", 0)
    file_writes = (io_api.get("WriteFile", 0) + io_api.get("NtWriteFile", 0)
                   + io_api.get("WriteFileEx", 0))
    rng_calls = (by_api.get("BCryptGenRandom", 0) + by_api.get("SystemFunction036", 0)
                  + by_api.get("RtlGenRandom", 0))
    total_crypto = sum(by_kind.values())
    rng_ratio = (rng_calls / total_crypto) if total_crypto > 0 else 0.0
    sleep_calls = (by_api.get("NtDelayExecution", 0) + by_api.get("Sleep", 0)
                    + by_api.get("SleepEx", 0))
    flags = []
    if encrypt_calls == 0:
        flags.append("no_encryption_observed")
    if file_writes < 5:
        flags.append("no_file_writes")
    if total_crypto > 50 and rng_ratio > 0.8 and encrypt_calls == 0:
        flags.append("rng_only_no_encrypt")
    if sleep_calls > 100 and encrypt_calls == 0:
        flags.append("sleep_loops_no_encrypt")
    suspected = len(flags) >= 2
    return {
        "suspected": suspected,
        "flags": flags,
        "encrypt_calls": encrypt_calls,
        "file_writes": file_writes,
        "rng_calls": rng_calls,
        "rng_ratio": round(rng_ratio, 3),
        "sleep_calls": sleep_calls,
    }

def adapt(ar: dict, trace_root: Path, dll_roles: dict | None = None) -> dict:
    """Build the unified 'view' that all three report writers consume."""
    family = _family_tag(ar, trace_root)
    session_id = _session_id_from(trace_root)
    exec_quality = _infer_execution_quality(ar)
    # Resolve PIN-attach failure BEFORE the tier is computed: a pin-attach failure
    # left as 'indeterminate' would otherwise collapse to INFEASIBLE (confident
    # no-match) instead of the correct NO_PAYLOAD_RUN (the payload never ran).
    pin_attach_failed = _pin_attach_failed(trace_root)
    if pin_attach_failed and exec_quality not in ("pin_attach_failed",):
        exec_quality = "pin_attach_failed"

    rc_passed = _strict_passed_cases(ar)
    rc_failed = _failed_cases(ar)
    rc_total = int(_safe_get(ar, "recovery_cases", "total_cases", default=7) or 7)
    rc_passed_count = len(rc_passed)
    tier = _recovery_tier(rc_passed_count, rc_total, exec_quality)
    # VALIDATED flag: paper §III — only engaged after offline byte-level
    # round-trip recovers ≥50% of captured ciphertexts. We never run that
    # round-trip in this pipeline, so it is always false here.
    validated = False

    primary_cipher, primary_conf = _primary_cipher(ar)
    chain_depth = _key_chain_depth(ar)
    by_cat, by_label = _loop_category_breakdown(ar)
    top_loops = _scored_loops(ar, n=10)
    dll_break = _dll_role_breakdown(ar, dll_roles, trace_root=trace_root)
    dll_names = _loaded_dll_names(ar, trace_root=trace_root)

    runtime_obj = _safe_get(ar, "runtime", default={}) or {}
    runtime_sec = runtime_obj.get("seconds")
    peak_wss = runtime_obj.get("peak_working_set_bytes")
    runtime_source = "analysis_report"
    if runtime_sec is None or peak_wss is None:
        sidecar = _ransomflow_done(trace_root) or {}
        if runtime_sec is None and sidecar.get("runtime_seconds") is not None:
            runtime_sec = sidecar.get("runtime_seconds")
            runtime_source = "ransomflow_done"
        if peak_wss is None:
            peak_wss = sidecar.get("peak_working_set_bytes")
    if runtime_sec is None:
        # PIN crashed mid-run; estimate from artifact mtime spread.
        rt_est, src = _runtime_from_mtimes(trace_root)
        if rt_est is not None:
            runtime_sec = rt_est
            runtime_source = src
    api_counts = {
        "BCryptGenRandom": _api_count(ar, "BCryptGenRandom"),
        "SystemFunction036": _api_count(ar, "SystemFunction036"),
        "ProcessPrng": _api_count(ar, "ProcessPrng"),
        "CryptGenRandom": _api_count(ar, "CryptGenRandom"),
        "RtlGenRandom": _api_count(ar, "RtlGenRandom"),
        "BCryptEncrypt": _api_count(ar, "BCryptEncrypt"),
        "CryptEncrypt": _api_count(ar, "CryptEncrypt"),
        "BCryptExportKey": _api_count(ar, "BCryptExportKey"),
        "CryptExportKey": _api_count(ar, "CryptExportKey"),
        "NtWriteFile": _api_count(ar, "NtWriteFile"),
        "WriteFile": _api_count(ar, "WriteFile"),
        "NtReadFile": _api_count(ar, "NtReadFile"),
        "ReadFile": _api_count(ar, "ReadFile"),
        "MoveFileW": _api_count(ar, "MoveFileW"),
        "MoveFileExW": _api_count(ar, "MoveFileExW"),
        "DeleteFile": _api_count(ar, "DeleteFile"),
        "DeleteFileW": _api_count(ar, "DeleteFileW"),
        "CreateFile": _api_count(ar, "CreateFile"),
        "CreateFileW": _api_count(ar, "CreateFileW"),
    }
    rng_total = sum(api_counts[k] for k in HOOKED_RNG)
    sym_encrypt_total = api_counts["BCryptEncrypt"] + api_counts["CryptEncrypt"]
    # original `_safe_get(..., default=0) or A+B` collapses
    # a legitimate stage5 reading of 0 (no writes happened) to the API-count
    # fallback. Distinguish 'absent' from 'present and zero' by using
    # default=None and an explicit None check.
    _w = _safe_get(ar, "behavior_profile", "stage5_fileops", "writes", default=None)
    writes_total = _w if _w is not None else (api_counts["NtWriteFile"] + api_counts["WriteFile"])
    _r = _safe_get(ar, "behavior_profile", "stage5_fileops", "reads", default=None)
    reads_total = _r if _r is not None else (api_counts["NtReadFile"] + api_counts["ReadFile"])
    _d = _safe_get(ar, "behavior_profile", "stage5_fileops", "deletes", default=None)
    deletes_total = _d if _d is not None else (api_counts["DeleteFile"] + api_counts["DeleteFileW"])
    _m = _safe_get(ar, "behavior_profile", "stage5_fileops", "moves", default=None)
    moves_total = _m if _m is not None else (api_counts["MoveFileW"] + api_counts["MoveFileExW"])

    sym_keys_list = _safe_get(ar, "crypto_global", "sym_keys", default=[]) or []
    asym_blobs_list = _safe_get(ar, "crypto_global", "asym_blobs", default=[]) or []
    sym_keys_unique = len({(sk.get("hex") if isinstance(sk, dict) else None) for sk in sym_keys_list} - {None})

    chain_stats = _safe_get(ar, "chain", "stats", default={}) or {}
    embedded_root_count = int(chain_stats.get("embedded_root_count") or 0)
    sink_count = int(chain_stats.get("sink_count") or 0)
    hardcoded_key_ratio = float(chain_stats.get("hardcoded_key_ratio") or 0.0)

    residue = _safe_get(ar, "residue", default={}) or {}
    residue_class = (residue.get("residue_class") or "NONE").upper()

    evidence_tree = _evidence_tree(ar)

    # Key Detection / File Recoverability / Loop-Based Behavior Recovery (per-sample metrics)
    paper_key_detection = "yes" if (
        rng_total > 0 or sym_keys_unique > 0 or len(asym_blobs_list) > 0
        or residue_class in ("MID", "HIGH")
    ) else "no"
    paper_file_recoverable = "yes" if (
        rc_passed_count > 0 and writes_total > 0
    ) else ("partial" if rc_passed_count > 0 else "no")
    # exclude sha2/xor noise from triggering this gap row "yes".
    paper_loop_recovery = "no"
    for _lp in top_loops:
        _lbl = _lp.get("label") or ""
        if not _lbl.startswith("crypto."):
            continue
        if _is_not_cipher(_lbl): 
            continue
        paper_loop_recovery = "yes"
        break

    return {
        "family": family,
        "session_id": session_id,
        "trace_root": str(trace_root),
        "execution_quality": exec_quality,
        "runtime_sec": runtime_sec,
        "runtime_source": runtime_source if runtime_sec is not None else "none",
        "peak_wss": peak_wss,
        "pin_attach_failed": pin_attach_failed,
        "primary_cipher": primary_cipher,
        "primary_cipher_confidence": primary_conf,
        "key_chain_depth": chain_depth,
        "recovery": {
            "passed_cases": rc_passed,
            "failed_cases": rc_failed,
            "passed_count": rc_passed_count,
            "total_cases": rc_total,
            "tier": tier,
            "validated": validated,
        },
        "loop_by_category": by_cat,
        "loop_by_label": by_label,
        "top_scored_loops": top_loops,
        "dll_roles": dll_break,
        "loaded_dlls": dll_names,
        "api_counts": api_counts,
        "totals": {
            "rng_calls": rng_total,
            "sym_encrypt_calls": sym_encrypt_total,
            "writes": writes_total,
            "reads": reads_total,
            "deletes": deletes_total,
            "moves": moves_total,
            "loops_total": _safe_get(ar, "behavior_profile", "stage3_loops", "total_hot_loops", default=0) or 0,
            "loops_crypto": len([l for l in (top_loops or []) if (l.get("label") or "").startswith("crypto.")]),
            "sym_keys_unique": sym_keys_unique,
            "asym_blobs": len(asym_blobs_list),
            "embedded_root_count": embedded_root_count,
            "sink_count": sink_count,
            "hardcoded_key_ratio": hardcoded_key_ratio,
        },
        "residue": {
            "class": residue_class,
            "total_matches": residue.get("total_matches", 0),
            "unique_tags_with_hit": residue.get("unique_tags_with_hit", 0),
            "snapshots_scanned": residue.get("snapshots_scanned", 0),
        },
        # surface cipher_constants + byte_signatures sub-results
        # in sample_view so that paper readers can distinguish
        #   (a) "scanner ran and found nothing"     (legitimate 0 hits)
        #   (b) "scanner didn't run / key missing"  (None from dict.get())
        # Previously these were absent from sample_view, so dict.get()
        # returned None and made (a) look like (b).
        "cipher_constants": (lambda cc: {
            "status": cc.get("status"),
            "hits_count": len(cc.get("hits") or []),
            "scanned_loops_with_hit": len(cc.get("by_loop") or {}),
            "by_constant_count": len(cc.get("by_constant") or {}),
            "reason": cc.get("reason"),
        })(ar.get("cipher_constants") or {}),
        "byte_signatures": (lambda bs: {
            "aeskeyfind_count":      len(bs.get("aeskeyfind_hits") or []),
            # The scanner recovers the actual key bytes at each hit. Collapsing the hit
            # list to a count discarded them, so an operator reading a fired RC-06 saw
            # "aeskeyfind(15)" and had nothing to try. Carry the keys through.
            "aeskeyfind_keys":       sorted({h.get("key_hex") for h in (bs.get("aeskeyfind_hits") or [])
                                             if h.get("key_hex")}),
            "bcrypt_rsa_blob_count": len(bs.get("bcrypt_rsa_blob_hits") or []),
            "cryptoapi_rsa_blob_count":   len(bs.get("cryptoapi_rsa_blob_hits") or []),
            "avaddon_session_count": len(bs.get("avaddon_session_hits") or []),
            "wanakiwi_prime_count":  len(bs.get("wanakiwi_prime_hits") or []),
            "rsa_moduli_in_chain":   bs.get("rsa_moduli_in_chain", 0),
            "snapshots_scanned":     bs.get("snapshots_scanned", residue.get("snapshots_scanned", 0)),
        })(ar.get("byte_signatures") or {}),
        "cross_axis": _safe_get(ar, "cross_axis", "verdict_counts", default={}) or {},
        # paper §IV behavioral evidence + anti-analysis evasion detector
        "behavioral": _extract_behavioral_evidence(ar),
        "evasion": _detect_evasion_suspected(ar),
        # surface analysis stages that were previously not exposed
        # in sample_view, so a reader can see WHY a primary_cipher /
        # family / RC tier was chosen — not just the final label. All four
        # blocks are deterministic projections of analysis_report.json
        # (counts only; no heuristic transformation).
        "sym_key_inference": (lambda s: {
            "total_keys":         int(s.get("total_keys", 0) or 0),
            "with_algorithm_in":  int(s.get("with_algorithm_in", 0) or 0),
            "inferred":           int(s.get("inferred", 0) or 0),
            "rules_loaded":       int(s.get("rules_loaded", 0) or 0),
            "by_inferred_algo":   s.get("by_inferred_algo") or {},
        })(ar.get("sym_key_inference") or {}),
        "chain_stats": (lambda c: {
            **((c.get("stats") or {})),
            "rng_to_keygen_paths_count": len(c.get("rng_to_keygen_paths") or []),
            "sinks_count":                len(c.get("sinks") or []),
            "embedded_roots_count":       len(c.get("embedded_roots") or []),
        })(ar.get("chain") or {}),
        "loop_clusters_summary": (lambda lc: {
            **((lc.get("stats") or {})),
            "unique_cluster_ids": len(lc.get("clusters") or {}),
        })(ar.get("loop_clusters") or {}),
        "behavior_profile_summary": (lambda bp: (
            # Helper: a stage field is either an int count or a list of ids
            # (e.g. crypto_label_loops can be either depending on stage
            # configuration). Normalise both to an int so sample_view stays
            # type-stable for downstream consumers (paper aggregation).
            lambda _n: {
                "algorithms_detected_via_apis":
                    bp.get("algorithms_detected_via_apis") or [],
                "stage1_dll_count":
                    _n((bp.get("stage1_init") or {}).get("dll_count")),
                "stage2_rng_calls":
                    _n((bp.get("stage2_keygen") or {}).get("rng_calls")),
                "stage2_keygen_calls":
                    _n((bp.get("stage2_keygen") or {}).get("keygen_calls")),
                "stage2_kdf_calls":
                    _n((bp.get("stage2_keygen") or {}).get("kdf_calls")),
                "stage3_total_hot_loops":
                    _n((bp.get("stage3_loops") or {}).get("total_hot_loops")),
                "stage3_crypto_label_loops":
                    _n((bp.get("stage3_loops") or {}).get("crypto_label_loops")),
                "stage3_crypto_call_loops":
                    _n((bp.get("stage3_loops") or {}).get("crypto_call_loops")),
                "stage3_io_loops":
                    _n((bp.get("stage3_loops") or {}).get("io_loops")),
                "stage4_sym_calls":
                    _n((bp.get("stage4_encrypt") or {}).get("sym_calls")),
                "stage4_asym_calls":
                    _n((bp.get("stage4_encrypt") or {}).get("asym_calls")),
                "stage4_memop_calls":
                    _n((bp.get("stage4_encrypt") or {}).get("memop_calls")),
                "stage5_opens":
                    _n((bp.get("stage5_fileops") or {}).get("opens")),
                "stage5_writes":
                    _n((bp.get("stage5_fileops") or {}).get("writes")),
                "stage5_reads":
                    _n((bp.get("stage5_fileops") or {}).get("reads")),
                "stage5_deletes":
                    _n((bp.get("stage5_fileops") or {}).get("deletes")),
                "stage5_moves":
                    _n((bp.get("stage5_fileops") or {}).get("moves")),
            }
        )(lambda v: (len(v) if isinstance(v, list)
                     else int(v or 0) if isinstance(v, (int, float, str))
                     else 0)))(ar.get("behavior_profile") or {}),
        "paper_metrics": {
            "key_detection": paper_key_detection,
            "file_recoverable": paper_file_recoverable,
            "loop_recovery": paper_loop_recovery,
        },
        "coverage_notes": _safe_get(ar, "behavior_profile", "coverage", "notes", default=[]) or [],
        "missing_inputs": _safe_get(ar, "behavior_profile", "coverage", "missing_for_full_analysis", default=[]) or [],
        "evidence_tree": evidence_tree,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

def load_analysis_report(trace_root: Path) -> tuple[dict | None, Path | None, str | None]:
    """Locate _analysis/proc_<pid>/_detail/analysis_report.json (or fallbacks)."""
    candidates: list[Path] = []
    analysis_dir = trace_root / "_analysis"
    if analysis_dir.exists():
        for proc_dir in sorted(analysis_dir.glob("proc_*")):
            detail = proc_dir / "_detail" / "analysis_report.json"
            if detail.exists():
                candidates.append(detail)
        flat = analysis_dir / "analysis_report.json"
        if flat.exists():
            candidates.append(flat)
    for proc_dir in sorted(trace_root.glob("proc_*")):
        detail = proc_dir / "_detail" / "analysis_report.json"
        if detail.exists():
            candidates.append(detail)
    for p in candidates:
        try:
            with p.open("r", encoding="utf-8") as fh:
                return json.load(fh), p, None
        except Exception as ex:
            return None, p, f"parse_error: {ex}"
    return None, None, "no_analysis_report"
