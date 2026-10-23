"""Single-command entry point: raw trace_<name>/ → 5 markdown reports.

Runs Stage 1 (main.py) then Stage 2 (report/generate.py) on the
given trace directory.

Usage:
    python onHost/run.py <trace_dir>
    python onHost/run.py --all <root>                  # every trace_* child
    python onHost/run.py --all <root> --skip-done      # skip if already done
    python onHost/run.py --all <root> --out-mirror <dir>
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent          # …/Ransack-main/onHost
ANALYZE_MAIN = HERE / "main.py"
REPORT_GEN   = HERE / "report" / "generate.py"


def _py() -> str:
    return sys.executable


# in quiet mode, surface captured stdout/stderr to the
# user's stderr on failure and persist them to <trace>/_analysis/_stage{1,2}.log
# so batch --all --quiet runs remain debuggable.
def _dump_captured(stage_name: str, trace: Path, r: subprocess.CompletedProcess) -> None:
    log_dir = trace / "_analysis"
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / f"_{stage_name}.log"
        with log_path.open("wb") as fh:
            if r.stdout:
                fh.write(b"--- stdout ---\n")
                fh.write(r.stdout if isinstance(r.stdout, bytes) else r.stdout.encode("utf-8", "replace"))
            if r.stderr:
                fh.write(b"\n--- stderr ---\n")
                fh.write(r.stderr if isinstance(r.stderr, bytes) else r.stderr.encode("utf-8", "replace"))
    except OSError:
        log_path = None
    sys.stderr.write(f"[{stage_name}] FAILED rc={r.returncode} on {trace.name}\n")
    for label, blob in (("stdout", r.stdout), ("stderr", r.stderr)):
        if not blob:
            continue
        text = blob.decode("utf-8", "replace") if isinstance(blob, bytes) else blob
        tail = "\n".join(text.splitlines()[-40:])
        sys.stderr.write(f"--- {label} tail ---\n{tail}\n")
    if log_path:
        sys.stderr.write(f"(full output: {log_path})\n")
    sys.stderr.flush()


def stage1(trace: Path, verbose: bool = True) -> int:
    if verbose:
        print(f"[stage 1] analyze -> {trace.name}", flush=True)
    t0 = time.perf_counter()
    r = subprocess.run([_py(), str(ANALYZE_MAIN), str(trace)],
                       capture_output=not verbose)
    if verbose:
        print(f"[stage 1] done in {time.perf_counter()-t0:.1f}s "
              f"(rc={r.returncode})", flush=True)
    # emit captured output on failure in quiet mode.
    if not verbose and r.returncode != 0:
        _dump_captured("stage1", trace, r)
    return r.returncode


def stage2(trace: Path, mirror: Path | None, verbose: bool = True) -> int:
    cmd = [_py(), str(REPORT_GEN), "--one", str(trace)]
    if mirror:
        cmd += ["--out-mirror", str(mirror)]
    if verbose:
        print(f"[stage 2] report  -> {trace.name}", flush=True)
    t0 = time.perf_counter()
    r = subprocess.run(cmd, capture_output=not verbose)
    if verbose:
        print(f"[stage 2] done in {time.perf_counter()-t0:.1f}s "
              f"(rc={r.returncode})", flush=True)
    # emit captured output on failure in quiet mode.
    if not verbose and r.returncode != 0:
        _dump_captured("stage2", trace, r)
    return r.returncode


def process_one(trace: Path, mirror: Path | None = None,
                skip_done: bool = False, verbose: bool = True) -> bool:
    if not trace.is_dir():
        print(f"  not a directory: {trace}", file=sys.stderr)
        return False
    # sample_view.json alone is a brittle completion marker
    # (a previous crash mid-report leaves it present; renaming the output in
    # report/generate.py silently disables skip). Require ALL five expected
    # reports to be present before treating the trace as done.
    if skip_done:
        paper_dir = trace / "_paper_report"
        expected = (
            "README.md",
            "flow_report.md",
            "report.md",
            "unified_report.md",
            "sample_view.json",
        )
        if paper_dir.is_dir() and all((paper_dir / name).exists() for name in expected):
            if verbose: print(f"  skip (done): {trace.name}", flush=True)
            return True
    if not (trace / "_analysis" / "summary.json").exists():
        if stage1(trace, verbose) != 0: return False
    elif verbose:
        print(f"[stage 1] skipped (already analysed): {trace.name}", flush=True)
    return stage2(trace, mirror, verbose) == 0


def main():
    ap = argparse.ArgumentParser()
    # argparse cannot reliably enforce 'required' on a
    # positional inside a mutually-exclusive group; drop the MX group and
    # validate manually so users get a clear usage message instead of an
    # obscure 'one of the arguments ... is required' error.
    ap.add_argument("trace", nargs="?", default=None)
    ap.add_argument("--all", default=None)
    ap.add_argument("--out-mirror", default=None)
    ap.add_argument("--skip-done", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    # enforce exactly one of (trace, --all) post-parse.
    if bool(args.trace) == bool(args.all):
        if args.trace and args.all:
            ap.error("specify either a positional <trace> OR --all <root>, not both")
        else:
            ap.error("specify a positional <trace> directory or --all <root>")

    mirror = Path(args.out_mirror) if args.out_mirror else None
    if mirror: mirror.mkdir(parents=True, exist_ok=True)
    verbose = not args.quiet

    if args.trace:
        sys.exit(0 if process_one(Path(args.trace), mirror, args.skip_done,
                                  verbose) else 1)

    root = Path(args.all)
    if not root.is_dir():
        print(f"root not a directory: {root}", file=sys.stderr); sys.exit(2)
    traces = sorted([p for p in root.iterdir()
                     if p.is_dir() and p.name.startswith("trace_")])
    if not traces:
        print(f"no trace_* under {root}", file=sys.stderr); sys.exit(3)
    total, ok = len(traces), 0
    t0 = time.perf_counter()
    for i, t in enumerate(traces, 1):
        print(f"\n==== [{i}/{total}] {t.name} ====", flush=True)
        if process_one(t, mirror, args.skip_done, verbose): ok += 1
    print(f"\n==== DONE: {ok}/{total} in {time.perf_counter()-t0:.0f}s ====")
    sys.exit(0 if ok == total else 1)


if __name__ == "__main__":
    main()
