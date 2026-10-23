#!/usr/bin/env python3
"""
GarrantyCrypt / GarrantyDecrypt recovery (key recovery: local RSA-1024 -> Salsa20, intermittent).

Scheme (G DATA analysis + reverse-engineered & verified byte-exact):
  - Per file: 36-byte key material = [32-byte Salsa20 key][4-byte nonce]. Body cipher = Salsa20
    (key=payload[0:32], nonce=payload[32:36] + b"\\x00\\x00\\x00\\x00").
  - INTERMITTENT encryption in 0x5000 (20 KiB) chunks; the Salsa20 keystream is RESET to counter 0 for
    every chunk (i.e. the same keystream is reused per chunk). Layout:
        * file <= 0x10000   : dense  — encrypt 0x5000, skip 0x800, repeat (<=3 chunks, fills the file).
        * file  > 0x10000   : 3 chunks at start / middle / end (last chunk ends at EOF).
  - The 36-byte key material is RSA-1024 (PKCS#1 v1.5, CryptoAPI little-endian) wrapped in a 132-byte footer
    = [4-byte prefix][128-byte RSA block]. Extension here: ".horseleader" (variants: .garrantydecrypt,
    .spyhunter, .zorin, ...).

Why recoverable: the RSA key pair is generated locally (CryptGenKey) and exported (CryptExportKey) — the
Ransack trace captures the private blob (validated N == p*q). With it we unwrap each file's Salsa20 key.

Usage:
  python garrantycrypt_recover.py recover-key --trace <proc_dir> [--out priv.pem]
  python garrantycrypt_recover.py decrypt     --in <enc_dir> --trace <proc_dir> --out <dir> [--ext .horseleader]
"""
import os, sys, glob, argparse, hashlib
from math import gcd

CHUNK = 0x5000
SKIP  = 0x800

def _parse_priv(d, off):
    if off < 8 or d[off-8] != 0x07: return None
    bl = int.from_bytes(d[off+4:off+8], "little")
    if bl not in (1024, 2048, 4096): return None
    e = int.from_bytes(d[off+8:off+12], "little")
    if e < 3 or e % 2 == 0: return None
    nb, h = bl//8, bl//16; p0 = off+12
    if p0+nb+2*h > len(d): return None
    n = int.from_bytes(d[p0:p0+nb], "little"); p0 += nb
    p = int.from_bytes(d[p0:p0+h], "little"); p0 += h
    q = int.from_bytes(d[p0:p0+h], "little")
    if p <= 1 or q <= 1 or p*q != n: return None
    return (n, e, pow(e, -1, (p-1)*(q-1)//gcd(p-1, q-1)), p, q, bl)

def recover_priv(proc_dir):
    for fn in sorted(glob.glob(os.path.join(proc_dir, "crypto_*.bin"))):
        d = open(fn, "rb").read(); i = d.find(b"RSA2")
        while i >= 0:
            k = _parse_priv(d, i)
            if k: return k, os.path.basename(fn)
            i = d.find(b"RSA2", i+1)
    return None, None

def _chunk_offsets(blen):
    """Encrypted-chunk start offsets for a body of length blen."""
    if blen <= CHUNK:
        return [0]
    if blen <= 0x10000:                      # dense: encrypt 0x5000, skip 0x800
        offs = []; pos = 0
        while pos < blen:
            offs.append(pos); pos += CHUNK + SKIP
        return offs
    # large: 3 chunks at start / middle / end
    last = blen - CHUNK
    mid = last // 2
    return [0, mid, last]

def decrypt_file(enc, key):
    from Crypto.Cipher import Salsa20
    n, e, dd, p, q, bl = key; nb = bl//8
    if len(enc) <= 132: return None
    body = enc[:-132]
    m = pow(int.from_bytes(enc[-128:][::-1], "big"), dd, n).to_bytes(nb, "big")
    if m[:2] != b"\x00\x02": return None
    j = m.find(b"\x00", 2); pay = m[j+1:]
    if len(pay) < 36: return None
    skey, nonce = pay[:32], pay[32:36] + b"\x00\x00\x00\x00"
    ks = Salsa20.new(key=skey, nonce=nonce).encrypt(bytes(CHUNK))   # counter resets per chunk
    out = bytearray(body)
    for off in _chunk_offsets(len(body)):
        t = min(CHUNK, len(body) - off)
        for x in range(t):
            out[off+x] = body[off+x] ^ ks[x]
    return bytes(out)

def _key_from_args(a):
    if getattr(a, "key", None):
        from Crypto.PublicKey import RSA
        r = RSA.import_key(open(a.key, "rb").read()); return (r.n, r.e, r.d, r.p, r.q, r.size_in_bits())
    k, src = recover_priv(a.trace)
    if not k: sys.exit("[-] no RSA private key recovered from trace")
    print(f"[+] recovered RSA-{k[5]} private key from {src} (N == p*q verified)"); return k

def main():
    ap = argparse.ArgumentParser(); sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("recover-key"); a.add_argument("--trace"); a.add_argument("--key"); a.add_argument("--out")
    b = sub.add_parser("decrypt"); b.add_argument("--in", dest="indir", required=True)
    b.add_argument("--trace"); b.add_argument("--key"); b.add_argument("--out", required=True)
    b.add_argument("--ext", default=".horseleader")
    args = ap.parse_args()
    key = _key_from_args(args)
    if args.cmd == "recover-key":
        if args.out:
            from Crypto.PublicKey import RSA
            open(args.out, "wb").write(RSA.construct((key[0], key[1], key[2], key[3], key[4])).export_key())
            print(f"[+] wrote {args.out}")
        return
    os.makedirs(args.out, exist_ok=True); ok = 0
    files = sorted(glob.glob(os.path.join(args.indir, "*"+args.ext)))
    for f in files:
        base = os.path.basename(f)[:-len(args.ext)]
        dec = decrypt_file(open(f, "rb").read(), key)
        if dec is None: print(f"  [--] {base}: unwrap failed"); continue
        open(os.path.join(args.out, base), "wb").write(dec)
        print(f"  [OK] {base} ({len(dec)} B, sha256={hashlib.sha256(dec).hexdigest()[:16]})"); ok += 1
    print(f"\n[+] {ok}/{len(files)} decrypted -> {args.out}")

if __name__ == "__main__":
    try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except: pass
    main()
