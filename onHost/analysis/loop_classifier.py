"""Apply `assets/loop_patterns.json` to a disassembled loop.

This is a slim port of the legacy `loop_semantic_classifier.py`.  Two
things have changed:

  - The legacy code parsed pre-formatted cluster_<hash>.md files; we feed
    it the structures produced by `disasm.disasm_loop`.
  - The legacy role-gate consumed `memory_map.json` + `dll_roles.json`;
    the new PinTool does not publish a memory map, so we gate using the
    per-loop `image_path` (basename) against `dll_roles.json`. Loops
    whose image is the main .exe are treated as `executable.target`
    (legacy convention).

Output per loop matches the legacy compact format so any reused renderer
or aggregator still works:
    {label, category, confidence, iters, instructions, header,
     image_module, image_role, activity, matches, suppressed_crypto}
"""
from __future__ import annotations

import json
import os
from collections import Counter


CRYPTO_CAPABLE_ROLES = {
    "crypto.provider",
    "crypto.primitive",
    "executable.target",
}
CRYPTO_LABEL_PREFIX = "crypto."

# Maximum number of pattern matches and suppressed-crypto entries to carry
# in the output (kept small to bound JSON size; all matches are scored before
# truncation so the top entry is always the highest-confidence hit).
_MAX_MATCHES_OUT = 5
_MAX_SUPPRESSED_OUT = 3

# Fallback confidence when a pattern in loop_patterns.json omits the
# "confidence" key — treated as "weak positive" (below any explicit value).
_DEFAULT_PATTERN_CONFIDENCE = 0.5


# use a.get(fld, 0) so missing PinTool activity keys
# (e.g. older builds without an xor counter) do not raise KeyError and
# silently kill classification for the whole loop.
def _act_pass(act_filter: dict, c: dict) -> bool:
    if not act_filter:
        return True
    a = c["activity"]
    for fld, val in act_filter.items():
        if fld == "mem_r_min" and a.get("mem_r", 0) < val: return False
        if fld == "mem_r_max" and a.get("mem_r", 0) > val: return False
        if fld == "mem_w_min" and a.get("mem_w", 0) < val: return False
        if fld == "mem_w_max" and a.get("mem_w", 0) > val: return False
        if fld == "calls_min" and a.get("calls", 0) < val: return False
        if fld == "calls_max" and a.get("calls", 0) > val: return False
        if fld == "calc_min"  and a.get("calc",  0) < val: return False
        if fld == "calc_max"  and a.get("calc",  0) > val: return False
        if fld == "xor_min"   and a.get("xor",   0) < val: return False
        if fld == "xor_max"   and a.get("xor",   0) > val: return False
    return True


def _seq_match(seq: list, mnems: list) -> bool:
    # True iff `seq` occurs as a CONTIGUOUS run inside `mnems`.
    # (Contiguous, not subsequence: a subsequence match over-inflated crypto.*
    # confidence.) A previous greedy single-pointer scan reset j to 0/1 on a
    # mismatch without backtracking, so it produced FALSE NEGATIVES on
    # self-overlapping patterns -- e.g. seq=[mov,mov,add,...] genuinely present
    # at offset 1 of [mov,mov,mov,add,...] was missed. Check every start
    # position instead (patterns are short, streams bounded).
    n, m = len(mnems), len(seq)
    if m == 0:
        return True
    if m > n:
        return False
    for i in range(n - m + 1):
        if mnems[i:i + m] == seq:
            return True
    return False


def _set_match(req: list, mnem_counts: Counter) -> bool:
    # accept a pre-computed Counter from classify_loop
    # rather than re-Counting on every pattern hit.
    return all(mnem_counts[r] > 0 for r in req)


def _any_match(opts: list, mnem_set: set) -> bool:
    # accept a pre-computed set.
    return any(o in mnem_set for o in opts)


def _any_mnem_count(constraints: list, mnem_counts: Counter) -> bool:
    # accept a pre-computed Counter.
    return all(mnem_counts[m] >= n for m, n in constraints)


def _norm(h) -> str:
    """Normalize an immediate to a lowercase hex string suitable for
    set comparison.

    Note:
      * Original used ``str(x).lower().lstrip("0x")`` which treats "0x" as
        a *character set* and incorrectly turns "0deadbeef" into "deadbeef".
        Now we only strip the literal 0x/0X prefix.
      * Original used ``zfill(8)`` unconditionally, truncating-by-padding
        is not the issue but treating 64-bit immediates inconsistently was:
        a 16-hex-char value would lose its leading characters when compared
        with an 8-padded needle. We now only pad up to 8 (32-bit width);
        longer immediates are left untouched so 64-bit constants match.
    """
    # handle negative immediates / signed displacements.
    # Capstone emits things like '-0x10'; previously this fell through to
    # zfill(8) and produced meaningless '00000-16' / '-0x000010' values
    # that never matched anything. We strip the sign, convert to unsigned
    # 64-bit two's complement, then zero-pad for set comparison.
    s = str(h).lower().strip()
    neg = False
    if s.startswith("-"):
        neg = True
        s = s[1:]
    if s.startswith("0x"):
        s = s[2:]
    if neg:
        try:
            val = int(s, 16)
            s = format(((-val) & 0xFFFFFFFFFFFFFFFF), "x")
        except ValueError:
            # Non-hex content after sign strip; leave as-is for safety.
            return s
    return s.zfill(8) if len(s) <= 8 else s


def _match_pattern(p: dict, c: dict) -> tuple[bool, float]:
    m = p.get("match", {})
    if not _act_pass(m.get("act", {}), c):
        return False, 0.0
    if "insts_min" in m and c["instructions"] < m["insts_min"]: return False, 0.0
    if "insts_max" in m and c["instructions"] > m["insts_max"]: return False, 0.0
    if "iters_min" in m and c["iters"] < m["iters_min"]: return False, 0.0
    if "iters_max" in m and c["iters"] > m["iters_max"]: return False, 0.0
    # classify_loop stashes the heavy derived structures
    # (Counter(mnemonics), set(mnemonics), normalized imm set) into c so
    # each of the ~50 patterns reuses them instead of rebuilding per call.
    mns          = c["mnemonics"]
    mnem_counts  = c["_mnem_counts"]
    mnem_set     = c["_mnem_set"]
    imm_set      = c["_imm_set"]
    if "seq" in m and not _seq_match(m["seq"], mns):
        return False, 0.0
    if "set" in m and not _set_match(m["set"], mnem_counts):
        return False, 0.0
    if "any" in m and not _any_match(m["any"], mnem_set):
        return False, 0.0
    if "any_mnem_count" in m and not _any_mnem_count(m["any_mnem_count"], mnem_counts):
        return False, 0.0
    if "imm_const_required_any" in m:
        needles = {_norm(x) for x in m["imm_const_required_any"]}
        if not (needles & imm_set):
            return False, 0.0
    if "imm_const_forbidden_any" in m:
        needles = {_norm(x) for x in m["imm_const_forbidden_any"]}
        if needles & imm_set:
            return False, 0.0
    # An ARX round is named by how far it turns. `amounts` lists the schedule,
    # `min` how many must appear, and `max_distinct` rejects a loop that turns
    # by so many different amounts that any schedule would meet it by chance.
    if "rot_schedule" in m:
        spec = m["rot_schedule"]
        want = set(spec.get("amounts") or [])
        seen = c["_rot_set"]
        cap = spec.get("max_distinct")
        if cap is not None and len(seen) > int(cap):
            return False, 0.0
        if len(want & seen) < int(spec.get("min") or len(want)):
            return False, 0.0
    return True, float(p.get("confidence", _DEFAULT_PATTERN_CONFIDENCE))


def load_patterns(path: str) -> list:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)["patterns"]


_KNOWN_ROLES = {
    "crypto.provider",
    "crypto.primitive",
    "executable.target",
    "library.unknown",
    "library.system",
    "library.runtime",
    "library.compression",
    "library.network",
    "library.ui",
}


def load_dll_roles(path: str) -> dict[str, str]:
    # validate role values. Previously a value of {} or
    # a list would silently pass through and break the downstream
    # `role in CRYPTO_CAPABLE_ROLES` membership test (or worse, raise on
    # unhashable types). We now require a string and fall back to
    # 'library.unknown' for invalid / unknown entries.
    if not path or not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    out: dict[str, str] = {}
    for k, v in (doc.get("roles") or {}).items():
        if str(k).startswith("_comment"):
            continue
        key = str(k).lower()
        if not isinstance(v, str):
            out[key] = "library.unknown"
            continue
        if v not in _KNOWN_ROLES:
            # Unknown role string: keep as-is but the caller's
            # crypto-capable set will simply not include it. We do not
            # rewrite to library.unknown here so operators can introduce
            # new role taxonomies without a code change.
            out[key] = v
            continue
        out[key] = v
    return out


def resolve_role(image_path: str, main_exe_base: str,
                  roles: dict[str, str]) -> tuple[str, str]:
    """Return (module_basename, role).  Sample's own image gets the
    `executable.target` role which permits crypto.* labels."""
    base = os.path.basename(image_path or "").lower()
    if not base:
        return "", "library.unknown"
    if main_exe_base and base == main_exe_base:
        return base, "executable.target"
    if base in roles:
        return base, roles[base]
    if base.endswith(".exe"):
        return base, "executable.target"
    return base, "library.unknown"


def classify_loop(loop: dict, patterns: list,
                   main_exe_base: str,
                   roles: dict[str, str]) -> dict:
    d = loop.get("_disasm") or {}
    # Iterations: prefer the final post-thread-exit count published in
    # loop_events.jsonl; fall back to iteration_at_capture from the meta.
    iters = loop.get("final_iterations")
    if iters is None:
        iters = loop.get("iteration_at_capture") or 0

    image_module, role = resolve_role(loop.get("image_path") or "",
                                       main_exe_base, roles)
    mnems_list = d.get("mnemonics") or []
    imms_list  = d.get("imm_consts") or []
    rot_list   = d.get("rot_amounts") or []
    # do not let `or` collapse a legitimate 0 from
    # disasm into the meta fallback — an empty-body loop with a real 0
    # count must stay 0 so disassembly failures are not masked by the
    # meta value.
    if "instruction_count_disasm" in d:
        _inst_count = d["instruction_count_disasm"] or 0
    else:
        _inst_count = d.get("instruction_count_meta", 0) or 0
    c = {
        "iters":        int(iters or 0),
        "instructions": _inst_count,
        "mnemonics":    mnems_list,
        "apis_called":  d.get("apis_called") or [],
        "imm_consts":   imms_list,
        "rot_amounts":  rot_list,
        "activity":     d.get("activity") or {"mem_r": 0, "mem_w": 0,
                                                "calls": 0, "calc": 0,
                                                "xor": 0},
        # pre-compute the heavy derived structures once;
        # _match_pattern reads them from c so we pay O(N) here instead of
        # O(P*N) across all ~50 patterns.
        "_mnem_counts": Counter(mnems_list),
        "_mnem_set":    set(mnems_list),
        "_imm_set":     {_norm(i) for i in imms_list},
        "_rot_set":     set(rot_list),
    }
    crypto_allowed = role in CRYPTO_CAPABLE_ROLES

    matches, suppressed = [], []
    for p in patterns:
        # validate pattern entry before use. A missing
        # 'name' previously raised KeyError mid-loop and killed the whole
        # classification; missing 'category' silently propagated None to
        # downstream consumers expecting a string.
        pname = p.get("name")
        if not isinstance(pname, str) or not pname:
            continue
        pcat = p.get("category") or "uncategorized"
        ok, conf = _match_pattern(p, c)
        if not ok:
            continue
        entry = {"name": pname, "category": pcat,
                 "confidence": conf}
        if pname.startswith(CRYPTO_LABEL_PREFIX) and not crypto_allowed:
            suppressed.append(entry)
            continue
        matches.append(entry)
    # Deterministic-tier policy applied at the classifier layer (mirror of
    # the schema-layer `_DETERMINISTIC_CIPHER_LABELS` tier). Without this,
    # a confidence-only ordering can let a noisy heuristic label (e.g.
    # crypto.xor_stream at confidence 0.90) outrank a deterministic label
    # (e.g. crypto.aes_software_sbox at confidence 0.85) on the same loop.
    # Tie-break order: (tier, -confidence, name) — guarantees cross-host
    # determinism.
    _DET_LABELS = frozenset({
        "crypto.aes_ni", "crypto.aes_software_sbox", "crypto.aes_mixcolumns",
        "crypto.chacha_quarter", "crypto.salsa20_quarter",
        "crypto.tea_round", "crypto.des_feistel_round",
        "crypto.bignum_montgomery", "crypto.bignum_modexp",
    })
    matches.sort(key=lambda x: (
        0 if (x.get("name") or "") in _DET_LABELS else 1,   # deterministic tier first
        -float(x.get("confidence") or 0.0),                  # confidence desc
        (x.get("name") or ""),                               # label alphabetical (cross-PC determinism)
    ))

    if matches:
        top = matches[0]
        out = {
            "label":     top["name"],
            "category":  top["category"],
            "confidence": round(float(top["confidence"]), 2),
        }
    else:
        out = {"label": "unknown.utility", "category": "fallback",
               "confidence": 0.0}

    out.update({
        "iters":        c["iters"],
        "instructions": c["instructions"],
        "header":       loop.get("header"),
        "image_module": image_module,
        "image_role":   role,
        "activity":     c["activity"],
        "matches":      matches[:_MAX_MATCHES_OUT],
        "suppressed_crypto": suppressed[:_MAX_SUPPRESSED_OUT],
    })
    return out


def classify_all(bundle: dict, patterns_path: str,
                   roles_path: str | None = None) -> dict[int, dict]:
    patterns = load_patterns(patterns_path)
    roles    = load_dll_roles(roles_path) if roles_path else {}
    main_exe_base = ""
    if bundle.get("main_exe"):
        main_exe_base = os.path.basename(bundle["main_exe"]).lower()
    out: dict[int, dict] = {}
    for lid in sorted(bundle["loops"].keys()):
        L = bundle["loops"][lid]
        out[lid] = classify_loop(L, patterns, main_exe_base, roles)
    return out
