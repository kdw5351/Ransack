#!/usr/bin/env python3
"""One-command validation check for the HDLocker blind decryptor.

Runs the *shipped* decryptor (../hdlocker_decrypt.py) in fully blind mode
(no originals, no --known-size) on ./locked/, then verifies every recovered
file is byte-exact against ./originals/. Writes VALIDATION.log and exits
non-zero if any file differs.

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
LOCK = os.path.join(HERE, "locked")
OUT = os.path.join(HERE, "recovered")
DECRYPTOR = os.path.join(HERE, os.pardir, "hdlocker_decrypt.py")
LOG = os.path.join(HERE, "VALIDATION.log")


def _sanitize(line):
    """Keep the committed log machine-independent: relativize this bundle's
    absolute paths and drop the nondeterministic (N.Ns) wall-clock timing."""
    for absp, rel in ((OUT, "recovered"), (HERE, ".")):
        for v in {absp, absp.replace("/", "\\"), absp.replace("\\", "/")}:
            line = line.replace(v, rel)
    return re.sub(r"\s*\(\d+(?:\.\d+)?\s*s\)", "", line)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def main():
    lines = []

    def out(s=""):
        print(s)
        lines.append(s)

    out("=" * 68)
    out("HDLocker blind decryptor -- validation check")
    out("=" * 68)
    out("scheme : TEA-16 custom-CBC, IV=0, magic 'HDLocker_', keyspace brute-force")
    out(f"decryptor: {os.path.relpath(DECRYPTOR, HERE)}")
    out("mode   : blind (no originals given to the decryptor, no --known-size)")
    out("")

    cmd = [sys.executable, DECRYPTOR, "--in-dir", LOCK, "--out-dir", OUT]
    out("$ python hdlocker_decrypt.py --in-dir locked --out-dir recovered")
    r = subprocess.run(cmd, capture_output=True, text=True)
    for ln in (r.stdout or "").splitlines():
        out("  " + _sanitize(ln))
    if r.returncode != 0:
        out("  [stderr] " + (r.stderr or "").strip())
        out("[FAIL] decryptor exited non-zero")
        _write(lines)
        return 1
    out("")

    names = sorted(os.listdir(ORIG))
    ok = fail = 0
    for name in names:
        op = os.path.join(ORIG, name)
        rp = os.path.join(OUT, name)
        if not os.path.isfile(rp):
            out(f"[MISS] {name}: not produced by decryptor")
            fail += 1
            continue
        ob = open(op, "rb").read()
        rb = open(rp, "rb").read()
        if ob == rb:
            out(f"[ OK ] {name}: byte-exact ({len(rb)} B, sha256={sha(rb)[:16]})")
            ok += 1
        else:
            out(f"[DIFF] {name}: MISMATCH (orig {sha(ob)[:16]} rec {sha(rb)[:16]})")
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
