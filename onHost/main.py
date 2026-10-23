"""Ransack host-side analysis driver.

    python main.py <trace_dir> [--out-dir <dir>] [--bitness 32|64] [-v]

Accepts either of two layouts for <trace_dir>:

  (a) A single PinTool out-dir — the directory that actually contains the
      JSONL chunks and loop_<N>.json files. The report is written next to
      the trace (or to --out-dir).

  (b) A trace ROOT that holds one or more `proc_<PID>/` subdirectories
      (the layout dumped by the host-side capture driver for samples that spawn children).
      In that case every proc gets its own report under
      `<trace_root>/_analysis/proc_<PID>/`, plus a roll-up
      `<trace_root>/_analysis/summary.json`.

Outputs per proc:
    report.md                     (top level)
    _detail/analysis_report.json
    _detail/behavior_profile.txt
    _detail/case_study.md
"""
from __future__ import annotations

import sys
try:  # keep stdout/stderr UTF-8 so status prints do not crash on cp949/cp1252 consoles
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

# Make `from analysis import ...` work when main.py is run as a script.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from analysis import analyze_trace as at  # noqa: E402


_PROC_DIR = re.compile(r"^proc_(\d+)$")


def _looks_like_proc_dir(path: str) -> bool:
    """A directory is a "proc dir" when it carries the raw PinTool artifacts
    that load_bundle() consumes. We probe for the per-loop meta or any of
    the chunked JSONL streams — these only ever appear inside a proc dir.

    `ransomflow_done.json` is NOT a reliable signal: the host-side capture driver
    also drops a copy at the trace ROOT (one level above proc_<PID>/) for samples
    that spawned a single child, so trusting it here would treat the root as a
    proc dir and miss the children."""
    if not os.path.isdir(path):
        return False
    for name in os.listdir(path):
        if name.startswith("loop_") and name.endswith(".json"):
            return True
        if name.startswith(("io_events_", "crypto_events_",
                            "key_residue_snapshots_", "images_")):
            return True
    return os.path.isfile(os.path.join(path, "loaded_dlls.json"))


def _find_proc_dirs(root: str) -> list[tuple[int, str]]:
    """Returns [(pid, abs_path), ...] sorted by pid."""
    out: list[tuple[int, str]] = []
    if not os.path.isdir(root):
        return out
    for name in sorted(os.listdir(root)):
        m = _PROC_DIR.match(name)
        if not m:
            continue
        path = os.path.join(root, name)
        if os.path.isdir(path):
            out.append((int(m.group(1)), os.path.abspath(path)))
    out.sort(key=lambda p: p[0])
    return out


def _proc_summary(result: dict) -> dict:
    """Distil one analyze_trace.run() result into a small dict for the
    cross-proc summary.json. Avoids carrying the heavy bundle/loop data."""
    bundle = result.get("bundle") or {}
    rc  = result.get("recovery") or {}
    res = result.get("residue") or {}
    ckh = result.get("cipher_constants") or {}
    ski = result.get("sym_key_inference") or {}
    return {
        "main_exe":            bundle.get("main_exe"),
        "runtime_seconds":     bundle.get("runtime_seconds"),
        "peak_working_set":    bundle.get("peak_working_set_bytes"),
        "dll_count":           bundle.get("dll_count"),
        "loop_count":          len(bundle.get("loops") or {}),
        "recovery_status":     rc.get("support_status"),
        "recovery_passed":     rc.get("passed_count"),
        "recovery_total":      rc.get("total_cases"),
        "feasible_strategies": rc.get("feasible_strategies") or [],
        "residue_class":       res.get("residue_class"),
        "residue_matches":     res.get("total_matches"),
        "cipher_const_status": ckh.get("status"),
        "cipher_const_hits":   sum((ckh.get("by_constant") or {}).values()),
        "sym_keys_total":      ski.get("total_keys"),
        "sym_keys_inferred":   ski.get("inferred"),
        "out_dir":             result.get("out_dir"),
    }


def _write_summary(summary_path: str, per_proc: dict[int, dict], trace_root: str) -> None:
    payload = {
        "_meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "trace_root":   trace_root,
            "proc_count":   len(per_proc),
        },
        "procs": {str(pid): info for pid, info in sorted(per_proc.items())},
    }
    os.makedirs(os.path.dirname(summary_path), exist_ok=True)
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def _print_proc_banner(pid: int, total: int, idx: int, proc_dir: str) -> None:
    print(f"\n=== proc {pid}  [{idx}/{total}]  {proc_dir} ===")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("trace_dir", help=(
        "PinTool out-dir OR a trace root containing proc_<PID> subdirs"))
    ap.add_argument("--out-dir", default=None, help=(
        "where to write per-proc reports (default: "
        "<trace_dir>/_analysis/proc_<PID> for multi-proc, or <trace_dir> "
        "itself for single-proc)"))
    ap.add_argument("--bitness", type=int, choices=(32, 64), default=None,
                     help="force x86 mode for capstone (default: auto-detect)")
    ap.add_argument("--patterns", default=None,
                     help="path to loop_patterns.json (default: ../assets/)")
    ap.add_argument("--roles", default=None,
                     help="path to dll_roles.json    (default: ../assets/)")
    ap.add_argument("--assets-dir", default=None,
                     help="override directory for crypto_constants/sym_key_inference rules")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    trace_dir = os.path.abspath(args.trace_dir)
    if not os.path.isdir(trace_dir):
        print(f"[!] not a directory: {trace_dir}", file=sys.stderr)
        return 2

    # Single-proc dir → analyze in place.
    if _looks_like_proc_dir(trace_dir):
        # default to <trace_dir>/_analysis so reports don't mix with raw trace artifacts (idempotent re-runs, consistent with multi-proc branch)
        out_dir = args.out_dir or os.path.join(trace_dir, "_analysis")
        try:
            at.run(trace_dir, out_dir=out_dir, bitness=args.bitness,
                    patterns_path=args.patterns, roles_path=args.roles,
                    assets_dir=args.assets_dir,
                    verbose=args.verbose)
        except FileNotFoundError as e:
            print(f"[!] {e}", file=sys.stderr)
            return 2
        print(f"\n[+] done -- outputs in {out_dir}")
        return 0

    # Otherwise look for proc_<PID> subdirs.
    procs = _find_proc_dirs(trace_dir)
    if not procs:
        print(f"[!] no PinTool artifacts in {trace_dir!r} and no proc_<PID>/ "
              f"subdirs found", file=sys.stderr)
        return 2

    out_root = args.out_dir or os.path.join(trace_dir, "_analysis")
    per_proc: dict[int, dict] = {}
    failures: list[tuple[int, str]] = []

    for i, (pid, pdir) in enumerate(procs, start=1):
        _print_proc_banner(pid, len(procs), i, pdir)
        proc_out = os.path.join(out_root, f"proc_{pid}")
        try:
            result = at.run(pdir, out_dir=proc_out, bitness=args.bitness,
                             patterns_path=args.patterns, roles_path=args.roles,
                             assets_dir=args.assets_dir,
                             verbose=args.verbose)
        # broaden exception handling so one bad proc doesn't poison the whole batch
        except FileNotFoundError as e:
            print(f"[!] proc {pid}: missing artifact — {e}", file=sys.stderr)
            failures.append((pid, f"FileNotFoundError: {e}"))
            continue
        except (json.JSONDecodeError, ValueError, KeyError, RuntimeError, MemoryError) as e:
            print(f"[!] proc {pid}: {type(e).__name__}: {e}", file=sys.stderr)
            if args.verbose:
                import traceback
                traceback.print_exc()
            failures.append((pid, repr(e)))
            continue
        except Exception as e:
            print(f"[!] proc {pid}: unexpected {type(e).__name__}: {e}", file=sys.stderr)
            if args.verbose:
                import traceback
                traceback.print_exc()
            failures.append((pid, repr(e)))
            continue
        per_proc[pid] = _proc_summary(result)

    # avoid clobbering a prior good summary.json with an empty one when every proc failed
    summary_path = os.path.join(out_root, "summary.json")
    if not per_proc:
        failed_summary_path = os.path.join(out_root, "summary.failed.json")
        _write_summary(failed_summary_path, per_proc, trace_dir)
        print(f"[!] all {len(procs)} procs failed; wrote {failed_summary_path} "
              f"(prior summary.json preserved)", file=sys.stderr)
        summary_path = failed_summary_path
    else:
        _write_summary(summary_path, per_proc, trace_dir)

    # ── concise stdout roll-up
    print(f"\n=== summary ({len(per_proc)} procs analysed, "
          f"{len(failures)} failed) ===")
    for pid, info in sorted(per_proc.items()):
        print(f"  proc {pid:>6}  "
              f"loops={info['loop_count']:>3}  "
              f"rc={info['recovery_passed']}/{info['recovery_total']} "
              f"({info['recovery_status']})  "
              f"residue={info['residue_class']}  "
              f"sym_keys={info['sym_keys_total']}")
    if failures:
        print()
        for pid, msg in failures:
            print(f"  FAIL proc {pid}: {msg}")
    print(f"\n[+] summary.json -> {summary_path}")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
