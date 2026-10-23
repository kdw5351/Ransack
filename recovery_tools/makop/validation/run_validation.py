#!/usr/bin/env python3
"""One-command validation check for the Makop key-free recovery.

Runs the *shipped* tool (../makop_recover.py `extract`) on ./proc/ (the deposited plaintext-
residue snapshots), then verifies each recovered file is byte-exact against one of
./originals/. Recovery is key-free, so the tool names outputs recovered_NNN.<kind>; we match
by content. Writes VALIDATION.log and exits non-zero if any original is not recovered.

Usage:  python run_validation.py
"""
import hashlib
import os
import re
import subprocess
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
ORIG = os.path.join(HERE, "originals")
PROC = os.path.join(HERE, "proc")
OUT = os.path.join(HERE, "recovered")
TOOL = os.path.join(HERE, os.pardir, "makop_recover.py")
LOG = os.path.join(HERE, "VALIDATION.log")


def _sanitize(line: str) -> str:
    for absp, rel in ((OUT, "recovered"), (PROC, "proc"), (HERE, ".")):
        for v in {absp, absp.replace("/", "\\"), absp.replace("\\", "/")}:
            line = line.replace(v, rel)
    return re.sub(r"\s*\(\d+(?:\.\d+)?\s*s\)", "", line)


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def main() -> int:
    lines = []

    def out(s=""):
        print(s)
        lines.append(s)

    out("=" * 68)
    out("Makop recovery -- validation check (key-free plaintext residue)")
    out("=" * 68)
    out("scheme : per-file AES key RSA-sealed; files reconstructed from encrypt-sink residue")
    out(f"tool     : {os.path.relpath(TOOL, HERE)}")
    out("")

    if os.path.isdir(OUT):
        for f in os.listdir(OUT):
            try:
                os.remove(os.path.join(OUT, f))
            except OSError:
                pass
    cmd = [sys.executable, TOOL, "extract", PROC, OUT]
    out("$ python makop_recover.py extract proc recovered")
    r = subprocess.run(cmd, capture_output=True, text=True)
    for ln in (r.stdout or "").splitlines():
        out("  " + _sanitize(ln))
    if r.returncode != 0:
        out("  [stderr] " + (r.stderr or "").strip())
        out("[FAIL] tool exited non-zero")
        _write(lines)
        return 1
    out("")

    rec = {}
    if os.path.isdir(OUT):
        for f in sorted(os.listdir(OUT)):
            p = os.path.join(OUT, f)
            if os.path.isfile(p):
                rec[sha(open(p, "rb").read())] = f
    names = sorted(os.listdir(ORIG))
    ok = 0
    fail = 0
    for name in names:
        ob = open(os.path.join(ORIG, name), "rb").read()
        h = sha(ob)
        if h in rec:
            out(f"[ OK ] {name}: byte-exact (recovered as {rec[h]}, {len(ob)} B, sha256={h[:16]})")
            ok += 1
        else:
            out(f"[MISS] {name}: no byte-exact match among recovered files")
            fail += 1
    out("")
    out("-" * 68)
    out(f"RESULT: {ok}/{len(names)} byte-exact, {fail} missing")
    out("=" * 68)
    _write(lines)
    return 0 if fail == 0 else 2


def _write(lines):
    with open(LOG, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
