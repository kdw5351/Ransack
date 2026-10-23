#!/usr/bin/env python3
"""
Crypt888 (a.k.a. MirCop) ransomware recovery (key brute-force; weak fixed-seed key derivation).

Scheme (reverse-engineered + verified byte-exact):
  - Whole-file **DES-CBC**, **IV = 0**, **PKCS#7 padding** (64-bit block); files renamed `Lock.<original>`.
  - The DES key is **build-fixed**: `key = MD5(seed)[:8]`, where `seed` is a hardcoded 3-byte string.
    On the analysed build `seed = b"888"` (the family's name) -> key `0a113ef6b61820da`, reused for
    every file (no per-file key, no RSA, no partial encryption).

Why recoverable: the key is derived (`CryptDeriveKey`) from a tiny **hardcoded** seed, so there is no
per-victim secret. The Ransack trace captures the 3-byte seed fed to `CryptHashData` (it appears as a
3-byte `crypto_<seq>.bin`); `MD5(seed)[:8]` is the DES key. If the seed is unknown it is brute-forceable
(2**24) against any known plaintext. This is the *key brute-force* class (cf. HDLocker) — universal for
the build, offline, no payment.

Usage:
  python crypt888_recover.py recover-key [--trace <proc_dir>] [--seed 888]
  python crypt888_recover.py decrypt --in <enc_dir> --out <dir> [--trace <proc_dir>] [--seed 888]
  python crypt888_recover.py decrypt --in <enc_dir> --out <dir> --brute --known-file <name> --known-hex <hdr>
"""
import os, sys, glob, argparse, hashlib

def des_key(seed: bytes) -> bytes:
    """Crypt888 key derivation: MD5(seed) truncated to the 8-byte DES key (legacy CryptDeriveKey)."""
    return hashlib.md5(seed).digest()[:8]

def _pkcs7_unpad(d):
    if d and 1 <= d[-1] <= 8 and d[-d[-1]:] == bytes([d[-1]]) * d[-1]:
        return d[:-d[-1]]
    return d

def decrypt_blob(enc, key):
    from Crypto.Cipher import DES
    nb = len(enc) // 8
    return _pkcs7_unpad(DES.new(key, DES.MODE_CBC, bytes(8)).decrypt(enc[:nb * 8]))

def seed_from_trace(proc_dir):
    """The 3-byte hardcoded seed fed to CryptHashData is captured as a 3-byte crypto_*.bin; return it."""
    from collections import Counter
    c = Counter()
    for fn in glob.glob(os.path.join(proc_dir, "crypto_*.bin")):
        try:
            b = open(fn, "rb").read()
        except OSError:
            continue
        if len(b) == 3:
            c[b] += 1
    return c.most_common(1)[0][0] if c else None

def brute_key(enc_path, known_hdr):
    """Brute the 3-byte seed (2**24) against a known-plaintext header of one encrypted file (IV=0 block 0)."""
    from Crypto.Cipher import DES
    c0 = open(enc_path, "rb").read()[:8]
    n = max(8, len(known_hdr))
    full = open(enc_path, "rb").read()[:((n + 7) // 8) * 8]
    for v in range(0x1000000):
        k = des_key(v.to_bytes(3, "big"))
        if DES.new(k, DES.MODE_CBC, bytes(8)).decrypt(full)[:len(known_hdr)] == known_hdr:
            return k, v.to_bytes(3, "big")
    return None, None

def _resolve_key(args):
    if getattr(args, "key", None):
        return bytes.fromhex(args.key), None
    if getattr(args, "brute", False):
        enc = os.path.join(args.indir, args.known_file)
        k, seed = brute_key(enc, bytes.fromhex(args.known_hex))
        if not k:
            sys.exit("[-] brute-force found no 3-byte seed matching the known plaintext")
        print(f"[+] brute-forced seed = {seed!r} -> DES key {k.hex()}")
        return k, seed
    seed = None
    if getattr(args, "trace", None):
        seed = seed_from_trace(args.trace)
        if seed:
            print(f"[+] seed recovered from trace (CryptHashData input): {seed!r}")
    if seed is None:
        seed = (args.seed or "888").encode("latin1")
        print(f"[*] using seed {seed!r} (default/--seed)")
    return des_key(seed), seed

def main():
    ap = argparse.ArgumentParser(description="Crypt888/MirCop recovery (DES-CBC, MD5(seed)[:8] key)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("recover-key"); a.add_argument("--trace"); a.add_argument("--seed", default="888")
    b = sub.add_parser("decrypt"); b.add_argument("--in", dest="indir", required=True)
    b.add_argument("--out", required=True); b.add_argument("--trace"); b.add_argument("--seed", default="888")
    b.add_argument("--key"); b.add_argument("--ext", default=".*")
    b.add_argument("--brute", action="store_true"); b.add_argument("--known-file"); b.add_argument("--known-hex")
    args = ap.parse_args()

    if args.cmd == "recover-key":
        seed = seed_from_trace(args.trace) if args.trace else None
        seed = seed or (args.seed or "888").encode("latin1")
        print(f"[+] seed {seed!r} -> DES key {des_key(seed).hex()}")
        return

    key, _ = _resolve_key(args)
    os.makedirs(args.out, exist_ok=True)
    files = sorted(glob.glob(os.path.join(args.indir, "Lock.*")))
    ok = 0
    for f in files:
        base = os.path.basename(f)
        out_name = base[5:] if base.startswith("Lock.") else base + ".recovered"
        dec = decrypt_blob(open(f, "rb").read(), key)
        open(os.path.join(args.out, out_name), "wb").write(dec)
        print(f"  [OK] {out_name} ({len(dec)} B, sha256={hashlib.sha256(dec).hexdigest()[:16]})"); ok += 1
    print(f"\n[+] {ok}/{len(files)} decrypted -> {args.out}")

if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    main()
