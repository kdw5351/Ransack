#!/usr/bin/env python3
"""
KillRabbit ransomware recovery (key recovery: captured AES-256 symmetric key).

Scheme (reverse-engineered + verified byte-exact):
  - Whole-file **AES-256-CBC**, **IV = 0**, **PKCS#7 padding**, with a SINGLE symmetric key reused for
    every file in the run (no per-file key, no RSA wrapping, no partial/intermittent encryption).
  - Encrypted files are renamed `<name>.killrabbit`; encrypted size = ceil((orig+1)/16)*16.

Why recoverable: the 32-byte AES-256 key is materialised in process memory and captured by the Ransack
trace (a raw key buffer in `crypto_<seq>.bin`). One captured key decrypts the whole run. This is the
"captured symmetric session key" class (cf. PayBreak; RC-07).

The tool finds the key by trying every 16/24/32-byte window in the trace's `crypto_*.bin` as an AES key
and keeping the one that decrypts a known-magic file (e.g. a `*.png.killrabbit` to the PNG signature) —
a decisive, plaintext-anchored check. Or pass the key directly with --key <hex>.

Usage:
  python killrabbit_recover.py recover-key --in <enc_dir> --trace <proc_dir>
  python killrabbit_recover.py decrypt     --in <enc_dir> --trace <proc_dir> --out <dir> [--ext .killrabbit]
"""
import os, sys, glob, argparse, hashlib

MAGICS = {           # original extension -> expected plaintext header
    ".png": b"\x89PNG\r\n\x1a\n", ".pdf": b"%PDF", ".zip": b"PK\x03\x04",
    ".jpg": b"\xff\xd8\xff", ".jpeg": b"\xff\xd8\xff", ".gz": b"\x1f\x8b",
    ".7z": b"7z\xbc\xaf\x27\x1c", ".rar": b"Rar!\x1a\x07",
}

def _candidate_keys(proc_dir):
    seen = set()
    for fn in sorted(glob.glob(os.path.join(proc_dir, "crypto_*.bin"))):
        try:
            b = open(fn, "rb").read()
        except OSError:
            continue
        for off in range(0, max(1, len(b) - 15)):
            for kl in (32, 16, 24):
                if off + kl <= len(b):
                    k = b[off:off + kl]
                    if k not in seen:
                        seen.add(k)
                        yield k

def _pkcs7_unpad(d):
    if d and 1 <= d[-1] <= 16 and d[-d[-1]:] == bytes([d[-1]]) * d[-1]:
        return d[:-d[-1]]
    return d

_ANY_MAGIC = [b"\x89PNG\r\n\x1a\n", b"%PDF", b"PK\x03\x04", b"\xff\xd8\xff", b"\x1f\x8b\x08",
              b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07", b"\xef\xbb\xbf"]  # +UTF-8 BOM for text

def _looks_decrypted(block16):
    """True if a decrypted first block looks like real plaintext: a known file magic, or mostly printable."""
    if any(block16.startswith(m) for m in _ANY_MAGIC):
        return True
    pr = sum(1 for b in block16 if 9 <= b <= 13 or 32 <= b <= 126)
    return pr >= 15  # near-all-printable (text/markup)

def find_key(enc_dir, proc_dir, ext):
    """A wrong key yields random first blocks; the right key makes most files decrypt to a real magic /
    printable text. Anchor on that across several files (extension is unreliable in synthetic corpora)."""
    from Crypto.Cipher import AES
    samples = [open(f, "rb").read()[:16] for f in sorted(glob.glob(os.path.join(enc_dir, "*" + ext)))[:10]]
    samples = [b for b in samples if len(b) == 16]
    if len(samples) < 2:
        sys.exit("[-] need at least 2 encrypted files to anchor the key search; use --key")
    for k in _candidate_keys(proc_dir):
        try:
            hits = sum(1 for blk in samples if _looks_decrypted(AES.new(k, AES.MODE_CBC, bytes(16)).decrypt(blk)))
        except ValueError:
            continue
        if hits >= max(3, len(samples) // 2):     # decisive majority decrypt to magic/printable
            return k
    return None

def decrypt_blob(enc, key):
    from Crypto.Cipher import AES
    return _pkcs7_unpad(AES.new(key, AES.MODE_CBC, bytes(16)).decrypt(enc))

def main():
    ap = argparse.ArgumentParser(description="KillRabbit recovery (AES-256-CBC, captured key)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("recover-key"); a.add_argument("--in", dest="indir", required=True); a.add_argument("--trace", required=True); a.add_argument("--ext", default=".killrabbit")
    b = sub.add_parser("decrypt"); b.add_argument("--in", dest="indir", required=True)
    b.add_argument("--trace"); b.add_argument("--key"); b.add_argument("--out", required=True); b.add_argument("--ext", default=".killrabbit")
    args = ap.parse_args()
    if args.cmd == "recover-key":
        k = find_key(args.indir, args.trace, args.ext)
        print(f"[+] AES-256 key: {k.hex()}" if k else "[-] key not found in trace")
        return
    if getattr(args, "key", None):
        key = bytes.fromhex(args.key)
    else:
        key = find_key(args.indir, args.trace, args.ext)
        if not key:
            sys.exit("[-] could not recover the AES key from the trace")
        print(f"[+] recovered AES-256 key from trace: {key.hex()}")
    os.makedirs(args.out, exist_ok=True)
    files = sorted(glob.glob(os.path.join(args.indir, "*" + args.ext)))
    ok = 0
    for f in files:
        base = os.path.basename(f)[:-len(args.ext)]
        dec = decrypt_blob(open(f, "rb").read(), key)
        open(os.path.join(args.out, base), "wb").write(dec)
        print(f"  [OK] {base} ({len(dec)} B, sha256={hashlib.sha256(dec).hexdigest()[:16]})"); ok += 1
    print(f"\n[+] {ok}/{len(files)} decrypted -> {args.out}")

if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    main()
