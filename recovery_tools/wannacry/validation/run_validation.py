#!/usr/bin/env python3
"""One-command validation check for the WannaCry recovery tool.

Runs the *shipped* tool (../wannacry_recover.py `decrypt`) on ./locked/, letting it reconstruct
the victim RSA private key from the deposited PRIVATEKEYBLOB in ./proc/ (validated N==p*q),
unwrap each file's AES-128 key, and decrypt; then verifies every recovered file is byte-exact
against ./originals/. Writes VALIDATION.log and exits non-zero if any file differs.

Usage:  python run_validation.py
Deps:   pycryptodome  (pip install -r ../../../requirements.txt)
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
LOCK = os.path.join(HERE, "locked")
PROC = os.path.join(HERE, "proc")
OUT = os.path.join(HERE, "recovered")
TOOL = os.path.join(HERE, os.pardir, "wannacry_recover.py")
LOG = os.path.join(HERE, "VALIDATION.log")


def _sanitize(line: str) -> str:
    for absp, rel in ((OUT, "recovered"), (PROC, "proc"), (LOCK, "locked"), (HERE, ".")):
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
    out("WannaCry recovery -- validation check (RSA private-key recovery)")
    out("=" * 68)
    out("scheme : per-file AES-128-CBC; key RSA-2048 wrapped; victim private key recovered from proc/")
    out(f"tool     : {os.path.relpath(TOOL, HERE)}")
    out("")

    cmd = [sys.executable, TOOL, "decrypt", PROC, LOCK, OUT]
    out("$ python wannacry_recover.py decrypt proc locked recovered")
    r = subprocess.run(cmd, capture_output=True, text=True)
    for ln in (r.stdout or "").splitlines():
        out("  " + _sanitize(ln))
    if r.returncode != 0:
        out("  [stderr] " + (r.stderr or "").strip())
        out("[FAIL] tool exited non-zero")
        _write(lines)
        return 1
    out("")

    names = sorted(os.listdir(ORIG))
    ok = 0
    fail = 0
    for name in names:
        op = os.path.join(ORIG, name)
        rp = os.path.join(OUT, name)
        if not os.path.isfile(rp):
            out(f"[MISS] {name}: not produced by tool")
            fail += 1
            continue
        ob = open(op, "rb").read()
        rb = open(rp, "rb").read()
        if ob == rb:
            out(f"[ OK ] {name}: byte-exact ({len(rb)} B, sha256={sha(rb)[:16]})")
            ok += 1
        else:
            out(f"[DIFF] {name}: MISMATCH (orig sha={sha(ob)[:16]} rec sha={sha(rb)[:16]})")
            fail += 1
    out("")
    out("-" * 68)
    out(f"RESULT: {ok}/{len(names)} byte-exact, {fail} mismatched")
    out("=" * 68)
    _write(lines)
    return 0 if fail == 0 else 2


def _write(lines):
    with open(LOG, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
