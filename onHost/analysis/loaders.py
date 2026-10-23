"""Read every artifact a Ransack PinTool run drops into `-out_dir`.

Tool outputs (see Ransack/onVM/README.md).  Unified `<name>_<N>.<ext>`
naming everywhere; everything lives flat at the top of -out_dir:

    loaded_dlls.json                       - DLL summary (one-shot)
    loop_events.jsonl                      - one row per captured loop
                                             (one-shot at end-of-run)
    loop_<N>.json                          - per-loop control-flow meta
    loop_<N>.bin                           - per-loop body bytes
    io_events_<N>.jsonl                    - chunked I/O API events
    crypto_events_<N>.jsonl                - chunked crypto API events
    key_residue_snapshots_<N>.jsonl        - chunked key-birth index
    crypto_<N>.bin                         - key-birth memory snapshot
    images_<N>.jsonl                       - chunked image-load rows
    ransomflow_done.json                   - runtime + peak working set

This module returns a single `TraceBundle` dict the rest of the pipeline
can rely on without re-touching the filesystem.
"""
from __future__ import annotations

import json
import os
import re


def _read_json(path: str):
    # empty/corrupt JSON file no longer aborts the whole
    # trace. Some PinTool runs emit a zero-byte meta file when the loop
    # finishes before the meta is fully written (trace_Crypted reproducer).
    # Treat empty / unparseable as "no meta" rather than fatal.
    if not os.path.isfile(path):
        return None
    try:
        # errors="replace" so a stray non-UTF-8 byte (e.g. a CP949 path fragment
        # or a truncated multibyte sequence from a mid-write PinTool crash) degrades
        # to a replacement char rather than raising UnicodeDecodeError and aborting
        # the whole trace; UnicodeDecodeError is also caught defensively.
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            txt = f.read().strip()
            if not txt:
                return None
            return json.loads(txt)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return None


def _read_jsonl(path: str) -> list[dict]:
    if not os.path.isfile(path):
        return []
    rows: list[dict] = []
    # errors="replace" so a single line with invalid UTF-8 does not raise during
    # iteration (decoding happens in `for line in f`, outside the per-line try);
    # such a line simply fails json.loads below and is skipped, not fatal.
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


# Numeric-suffix matcher used to assemble chunked streams in order.
_CHUNK_FILE_RE = re.compile(r"^(?P<base>.+)_(?P<n>\d+)\.jsonl$")


def _read_jsonl_chunks(trace_dir: str, base: str,
                        max_chunks: int = 2000,
                        max_rows: int = 1_000_000) -> list[dict]:
    """Concatenate every `<base>_<N>.jsonl` chunk under `trace_dir` in
    ascending N order.  Returns [] when none exist (so callers can still
    iterate without guarding).

    Guard: some ransomware floods file I/O, so the PinTool
    emits tens of thousands of 128KB chunks (trace_Clay/BlackOut had ~45-50k
    io_events chunks). Reading them all OOMs/freezes the host. We cap at
    `max_chunks` files AND `max_rows` accumulated rows, then stop and append a
    truncation marker. Loop analysis is UNAFFECTED (loops live in separate
    loop_<N>.json/.bin files); only the IO/crypto event aggregate becomes a
    representative prefix for these pathological traces."""
    if not os.path.isdir(trace_dir):
        return []
    pairs: list[tuple[int, str]] = []
    for name in os.listdir(trace_dir):
        m = _CHUNK_FILE_RE.match(name)
        if not m:
            continue
        if m.group("base") != base:
            continue
        try:
            n = int(m.group("n"))
        except ValueError:
            continue
        pairs.append((n, os.path.join(trace_dir, name)))
    pairs.sort(key=lambda p: p[0])
    rows: list[dict] = []
    for idx, (_, p) in enumerate(pairs):
        if idx >= max_chunks or len(rows) >= max_rows:
            rows.append({"_truncated": True, "_base": base,
                         "_total_chunks": len(pairs), "_read_chunks": idx,
                         "_read_rows": len(rows)})
            break
        rows.extend(_read_jsonl(p))
        # post-extend check ensures a single fat chunk
        # cannot blow past max_rows by tens of thousands of rows. Truncate
        # rows to exactly max_rows so the OOM guard is tight, not approximate.
        if len(rows) >= max_rows:
            del rows[max_rows:]
            rows.append({"_truncated": True, "_base": base,
                         "_total_chunks": len(pairs),
                         "_read_chunks": idx + 1,
                         "_read_rows": len(rows)})
            break
    # Drop internal truncation markers from the event stream — they are bookkeeping,
    # not real events, and were miscounted as synthetic '?' entries by the io/crypto
    # summarizers. No consumer reads the marker (grep-confirmed).
    return [r for r in rows if not r.get("_truncated")]


def _hex_int(v) -> int:
    # original ternary had identical branches on both sides
    # (both int(s, 16)) making the no-0x branch dead code. Fix: numbers
    # without a 0x prefix are now parsed as decimal. Keep 0x/0X parsing as hex.
    # reject bool (subclass of int that would silently
    # become 0/1), accept str/int only; coerce other numeric types (numpy
    # int64, float from sci-notation) via best-effort int() before bailing.
    if isinstance(v, bool):
        return 0
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        try:
            return int(v)
        except (ValueError, OverflowError):
            return 0
    if not isinstance(v, str):
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0
    s = v.strip()
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s, 10)
    except (ValueError, TypeError):
        return 0


# Matches the canonical `loop_<N>.json` naming used by the PinTool.
_LOOP_FILE_RE = re.compile(r"^loop_(\d+)\.json$")


def discover_loop_metas(trace_dir: str) -> dict[int, str]:
    """Map loop_id -> absolute meta path. Keeps loops the trace dropped on
    disk even if loop_events.jsonl is truncated or missing."""
    out: dict[int, str] = {}
    if not os.path.isdir(trace_dir):
        return out
    for name in os.listdir(trace_dir):
        m = _LOOP_FILE_RE.match(name)
        if m:
            out[int(m.group(1))] = os.path.join(trace_dir, name)
    return out


def load_loop(trace_dir: str, loop_id: int, meta_path: str) -> dict:
    meta = _read_json(meta_path) or {}
    meta.setdefault("loop_id", loop_id)
    # Prefer the `snapshot_file` field the PinTool embeds in the meta JSON;
    # fall back to the canonical `loop_<N>.bin` name when absent.
    snap_name = meta.get("snapshot_file") or f"loop_{loop_id}.bin"
    snap_path = os.path.join(trace_dir, snap_name)
    snap_bytes = b""
    if os.path.isfile(snap_path):
        with open(snap_path, "rb") as f:
            snap_bytes = f.read()
    meta["_snapshot_path"] = snap_path
    meta["_snapshot_bytes"] = snap_bytes
    meta["header_int"]   = _hex_int(meta.get("header"))
    meta["backedge_int"] = _hex_int(meta.get("backedge"))
    meta["loop_end_int"] = _hex_int(meta.get("loop_end"))
    return meta


def load_bundle(trace_dir: str) -> dict:
    """Read every artifact under `trace_dir`. Missing files are tolerated;
    every consumer downstream guards on the field being present."""
    trace_dir = os.path.abspath(trace_dir)
    if not os.path.isdir(trace_dir):
        raise FileNotFoundError(trace_dir)

    loaded_dlls = _read_json(os.path.join(trace_dir, "loaded_dlls.json")) or {}
    # loop_events.jsonl is still one-shot (written by
    # WriteLoopCaptureSummaries at end-of-run), so a single _read_jsonl
    # is correct here.  Streaming JSONL outputs use chunked files
    # `<name>_<N>.jsonl`, gathered in numeric order.
    loop_events    = _read_jsonl(os.path.join(trace_dir, "loop_events.jsonl"))
    io_events      = _read_jsonl_chunks(trace_dir, "io_events")
    crypto_events  = _read_jsonl_chunks(trace_dir, "crypto_events")
    keybirth_snaps = _read_jsonl_chunks(trace_dir, "key_residue_snapshots")
    images         = _read_jsonl_chunks(trace_dir, "images")
    done           = _read_json(os.path.join(trace_dir, "ransomflow_done.json")) or {}

    # proc_info.json sits one level down under proc_<pid>/. Both the
    # trace-root path (`<trace>/ransomflow_done.json`'s image field) and
    # the per-proc `proc_info.json:image` field carry the same absolute
    # path the PinTool attached to. Surface them on the bundle so the
    # sample binary basename is available for report headers.
    #
    # Two cases the caller may pass us:
    #   (a) trace-root layout: trace_dir contains proc_<PID>/ subdirs,
    #       each holding its proc_info.json.
    #   (b) per-proc layout: trace_dir IS a proc_<PID>/ directory and
    #       holds proc_info.json directly (multi-process fan-out passes
    #       each proc_<PID>/ dir as trace_dir independently).
    proc_infos: dict[str, dict] = {}
    if os.path.isdir(trace_dir):
        # Case (b): proc_info.json directly in trace_dir.
        direct_pi_path = os.path.join(trace_dir, "proc_info.json")
        direct_pi = _read_json(direct_pi_path)
        if direct_pi:
            # prefer the PID embedded in proc_info.json
            # rather than munging trace_dir basename. basename() on paths
            # like 'C:\\traces\\' (drive root with trailing sep) returns ''
            # and the proc_self fallback then collides when multiple bundles
            # are merged. Embedded pid is authoritative.
            embedded_pid = direct_pi.get("pid") or direct_pi.get("PID")
            if embedded_pid is not None:
                key = f"proc_{embedded_pid}"
            else:
                key = os.path.basename(os.path.normpath(trace_dir)) or "proc_self"
            proc_infos[key] = direct_pi
        # Case (a): proc_<PID>/ subdirs.
        for entry in os.listdir(trace_dir):
            if not entry.startswith("proc_"):
                continue
            pi_path = os.path.join(trace_dir, entry, "proc_info.json")
            pi = _read_json(pi_path)
            if pi:
                proc_infos[entry] = pi
    main_exe_from_proc = None
    for pi in proc_infos.values():
        img = pi.get("image")
        if img:
            main_exe_from_proc = img
            break
    if not main_exe_from_proc:
        main_exe_from_proc = done.get("image")

    metas_by_id = discover_loop_metas(trace_dir)
    loops: dict[int, dict] = {}
    for lid, path in metas_by_id.items():
        loops[lid] = load_loop(trace_dir, lid, path)

    # Merge final iteration count from loop_events into per-loop meta when
    # available. The PinTool writes meta at capture time (iter==4) but
    # rewrites loop_events with the post-thread-exit total — the latter is
    # what classifiers should consume as "iters".
    for ev in loop_events:
        lid = ev.get("loop_id")
        if lid in loops:
            loops[lid]["final_iterations"] = ev.get("iterations")
            loops[lid]["thread_count_seen"] = ev.get("thread_count")

    return {
        "trace_dir":      trace_dir,
        "main_exe":       loaded_dlls.get("main_exe") or main_exe_from_proc,
        "dlls":           loaded_dlls.get("dlls") or [],
        "dll_count":      loaded_dlls.get("dll_count") or 0,
        "images":         images,
        "proc_infos":     proc_infos,
        "loops":          loops,
        "loop_events":    loop_events,
        "io_events":      io_events,
        "crypto_events":  crypto_events,
        "keybirth_snapshots": keybirth_snaps,
        "runtime_seconds":         done.get("runtime_seconds"),
        "peak_working_set_bytes":  done.get("peak_working_set_bytes"),
    }


