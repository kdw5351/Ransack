"""Build the legacy 5-stage narrative from the new minimal feed.

    Stage 1: Initialisation       (crypto provider DLLs loaded + open APIs)
    Stage 2: Key generation       (rand / keygen / kdf APIs)
    Stage 3: File traversal loops (hot loops + which loops did IO/crypto)
    Stage 4: Per-file encryption  (sym_enc / asym_enc / memop calls)
    Stage 5: Cleanup / shred      (handle_io + dir_io delete groups)

The legacy `behavior_profiler.profile()` consumed `crypto_chain.jsonl` —
a much richer event stream than the new PinTool emits. We do the best
the new feed allows and flag the missing pieces in `coverage`.
"""
from __future__ import annotations

CRYPTO_PROVIDER_DLLS = {
    "bcrypt.dll", "bcryptprimitives.dll", "ncrypt.dll", "advapi32.dll",
    "crypt32.dll", "cryptbase.dll", "cryptsp.dll", "rsaenh.dll",
    "libcrypto-3.dll", "libssl-3.dll",
    "libcrypto-3-x64.dll", "libssl-3-x64.dll",
    "mbedtls.dll", "libsodium.dll",
}

KEYGEN_KINDS  = {"keygen", "key_import"}
RAND_KINDS    = {"rand"}
KDF_KINDS     = {"kdf", "hash"}
SYM_KINDS     = {"sym_enc"}
ASYM_KINDS    = {"asym_enc", "key_export"}


def build(bundle: dict, loop_labels: dict, io_summary: dict,
           crypto_summary: dict) -> dict:
    dlls = bundle.get("dlls") or []
    dll_basenames = [d.get("base_name", "").lower() for d in dlls]
    crypto_dlls_loaded = sorted(b for b in dll_basenames
                                if b in CRYPTO_PROVIDER_DLLS)

    by_kind = crypto_summary.get("by_kind") or {}
    by_api  = crypto_summary.get("by_api")  or {}

    # API → kind map built once from the raw event stream; the summary
    # buckets discard the per-event linkage.
    api_to_kind = _api_to_kind(bundle.get("crypto_events") or [])
    rng_apis    = sorted({a for a, k in api_to_kind.items() if k in RAND_KINDS})
    keygen_apis = sorted({a for a, k in api_to_kind.items() if k in KEYGEN_KINDS})
    kdf_apis    = sorted({a for a, k in api_to_kind.items() if k in KDF_KINDS})
    sym_apis    = sorted({a for a, k in api_to_kind.items() if k in SYM_KINDS})
    asym_apis   = sorted({a for a, k in api_to_kind.items() if k in ASYM_KINDS})

    # ── Stage 3: loops ─────────────────────────────────────────────────
    crypto_label_loops = []
    io_loops          = []
    crypto_call_loops = []
    for lid, cls in loop_labels.items():
        if cls.get("label", "").startswith("crypto."):
            crypto_label_loops.append(lid)
        if io_summary.get("per_loop", {}).get(lid, {}).get("total", 0) > 0:
            io_loops.append(lid)
        if crypto_summary.get("per_loop", {}).get(lid, {}).get("crypto_calls", 0) > 0:
            crypto_call_loops.append(lid)

    # ── Stage 5: file ops grouped ──────────────────────────────────────
    by_api_io = io_summary.get("by_api") or {}
    deletes = _count_any(by_api_io, ("DeleteFile", "NtDeleteFile"))
    moves   = _count_any(by_api_io, ("MoveFile", "ReplaceFile",
                                       "SetFileInformationByHandle"))
    writes  = _count_any(by_api_io, ("WriteFile", "NtWriteFile"))
    reads   = _count_any(by_api_io, ("ReadFile", "NtReadFile"))
    opens   = _count_any(by_api_io, ("CreateFile", "NtCreateFile",
                                       "NtOpenFile", "OpenFile"))

    profile = {
        "stage1_init": {
            "crypto_dlls_loaded": crypto_dlls_loaded,
            "dll_count":          bundle.get("dll_count") or len(dlls),
        },
        "stage2_keygen": {
            "rng_apis":     rng_apis,
            "keygen_apis":  keygen_apis,
            "kdf_apis":     kdf_apis,
            "rng_calls":    sum(by_kind.get(k, 0) for k in RAND_KINDS),
            "keygen_calls": sum(by_kind.get(k, 0) for k in KEYGEN_KINDS),
            "kdf_calls":    sum(by_kind.get(k, 0) for k in KDF_KINDS),
        },
        "stage3_loops": {
            # consistent .get() — other call sites already
            # guard against a missing 'loops' key; do the same here.
            "total_hot_loops":      len(bundle.get("loops") or []),
            "crypto_label_loops":   sorted(crypto_label_loops),
            "io_loops":             sorted(io_loops),
            "crypto_call_loops":    sorted(crypto_call_loops),
        },
        "stage4_encrypt": {
            "sym_apis":  sym_apis,
            "asym_apis": asym_apis,
            "sym_calls":  sum(by_kind.get(k, 0) for k in SYM_KINDS),
            "asym_calls": sum(by_kind.get(k, 0) for k in ASYM_KINDS),
            "memop_calls":  sum(by_kind.get(k, 0) for k in ("memcpy", "normal_op")),
        },
        "stage5_fileops": {
            "opens":   opens,
            "reads":   reads,
            "writes":  writes,
            "deletes": deletes,
            "moves":   moves,
            "groups":  io_summary.get("by_group", {}),
        },
        "algorithms_detected_via_apis": _algorithms_via_apis(by_api),
        # What we couldn't compute because the PinTool no longer publishes it.
        "coverage": _coverage_notes(crypto_summary, io_summary),
    }
    return profile


def _api_to_kind(crypto_events: list[dict]) -> dict[str, str]:
    out: dict[str, str] = {}
    for ev in crypto_events:
        a = ev.get("api"); k = ev.get("kind")
        if a and k and a not in out:
            out[a] = k
    return out


def _count_any(d: dict, needles: tuple[str, ...]) -> int:
    """Sum the counts in ``d`` for keys whose basename matches any needle.

    original used a plain substring check
    (``n in k``), which counts unrelated symbols — e.g. needle="MoveFile"
    matched "ReOpenFile" (it does not, but it would match
    "RtlMoveMemory"), inflating fileop totals.  The matching rule is now:

        * exact: ``k == n``
        * unqualified prefix: ``k.startswith(n)`` (e.g. needle "MoveFile"
          accepts "MoveFileW", "MoveFileExW")
        * module-qualified suffix: ``k.endswith("!" + n)`` (e.g. needle
          "MoveFile" accepts "kernel32.dll!MoveFile")
    """
    out = 0
    for k, v in d.items():
        for n in needles:
            if k == n or k.startswith(n) or k.endswith("!" + n):
                out += v
                break
    return out


def _algorithms_via_apis(by_api: dict) -> list[str]:
    from .crypto_summary import algorithms_detected
    return algorithms_detected(by_api)


def _coverage_notes(crypto_summary: dict, io_summary: dict) -> dict:
    """Surface the bits the new feed cannot resolve so the report can
    flag them up-front (and so future PinTool changes are scoped)."""
    notes = []
    if not crypto_summary.get("by_kind"):
        notes.append("no_crypto_events")
    only_memop = (set(crypto_summary.get("by_kind") or {}).issubset(
                    {"memcpy", "normal_op"}))
    if only_memop and crypto_summary.get("total_events", 0) > 0:
        notes.append("crypto_feed_is_memop_only")
    if not io_summary.get("by_group"):
        notes.append("no_io_events")
    return {
        "notes": notes,
        "missing_for_full_analysis": [
            "buffer_bytes",       # crypto args[] are register values, not derefs
            "key_derivation_tags",  # no parent/child tag system on events
            "io_file_paths",        # io args[] are pointers, not strings
            "image_module_map",     # no per-IP -> module table at host side
        ],
    }


def render_text(P: dict) -> str:
    lines = []
    lines.append("RANSOMWARE BEHAVIOR PROFILE (Ransack)")
    lines.append("=" * 60)
    lines.append("")
    lines.append("Algorithms detected via APIs: "
                 + ", ".join(P.get("algorithms_detected_via_apis") or ["(none)"]))
    lines.append("")
    s1 = P["stage1_init"]
    lines.append(f"[Stage 1] Init - crypto provider DLLs loaded: "
                 f"{s1['crypto_dlls_loaded'] or '(none)'} "
                 f"(total dlls={s1['dll_count']})")
    s2 = P["stage2_keygen"]
    lines.append(f"[Stage 2] Keygen - rng_apis={s2['rng_apis']} "
                 f"keygen_apis={s2['keygen_apis']} kdf_apis={s2['kdf_apis']}")
    lines.append(f"            calls: rng={s2['rng_calls']} "
                 f"keygen={s2['keygen_calls']} kdf={s2['kdf_calls']}")
    s3 = P["stage3_loops"]
    lines.append(f"[Stage 3] Loops - total={s3['total_hot_loops']} "
                 f"crypto-label={len(s3['crypto_label_loops'])} "
                 f"with-io={len(s3['io_loops'])} "
                 f"with-crypto-call={len(s3['crypto_call_loops'])}")
    s4 = P["stage4_encrypt"]
    lines.append(f"[Stage 4] Encrypt - sym_apis={s4['sym_apis']} "
                 f"(calls={s4['sym_calls']}) "
                 f"asym_apis={s4['asym_apis']} (calls={s4['asym_calls']})")
    lines.append(f"            memop_calls={s4['memop_calls']}")
    s5 = P["stage5_fileops"]
    lines.append(f"[Stage 5] Fileops - opens={s5['opens']} reads={s5['reads']} "
                 f"writes={s5['writes']} deletes={s5['deletes']} moves={s5['moves']}")
    lines.append(f"            io_groups={s5['groups']}")
    lines.append("")
    cov = P.get("coverage", {})
    if cov.get("notes"):
        lines.append("[Coverage] " + ", ".join(cov["notes"]))
    if cov.get("missing_for_full_analysis"):
        lines.append("[Coverage] missing: "
                     + ", ".join(cov["missing_for_full_analysis"]))
    return "\n".join(lines)
