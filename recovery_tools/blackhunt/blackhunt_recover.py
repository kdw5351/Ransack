#!/usr/bin/env python3
"""
BlackHunt ransomware recovery tool (.Black / .Hunt2 / custom-ext variants).

Scheme (reverse-engineered from a Ransack-instrumented run; verified byte-exact vs known originals):
  - Per file the encryptor generates 64 bytes of key material: [32B ChaCha key][8B nonce][24B unused].
  - The 64 bytes are RSA-2048 / PKCS#1 v1.5 encrypted (CryptoAPI little-endian) and stored in a per-file
    footer:  [body ciphertext]["RISEN\\0" magic][256B RSA-wrapped key, LE]["<ext>\\0" UTF-16LE marker][flags]
  - Body cipher = ChaCha8 (8 rounds — the Conti encryptor; original Bernstein layout: 64-bit counter ||
    64-bit nonce). key = payload[0:32], nonce = payload[32:40], counter starts at 0.

  Memory-mapped, size-tiered body encryption (measured on the analysed build):
    * <= 512 KiB         : one mapped view, fully & continuously ChaCha8-encrypted.
    * ~0.5-a few MiB     : multiple 512 KiB (0x80000) views; a Conti-lineage desync leaves GAP=5 plaintext
                           bytes at each view boundary while the keystream counter keeps advancing.
    * very large (>~MiB) : INTERMITTENT — only 1 MiB (0x100000) blocks are encrypted, evenly spaced, with
                           large plaintext gaps between; keystream is continuous across encrypted blocks
                           only (cumulative). The plaintext gaps are left in clear by the malware.

  Continuous decryption is byte-exact for the first mapped view (<=512 KiB) on any build — that covers
  the great majority of victim files. The 512 KiB-view GAP and the intermittent-block layout are
  build/size specific; defaults below reproduce the analysed sample byte-exact (see README.md, Recovery details).

Recovery requires the victim RSA-2048 PRIVATE key, recovered from the Ransack trace (CryptoAPI PRIVATEKEYBLOB,
validated by N == p*q). Without the trace, pass the key with --key <priv.pem>.

Usage:
  recover-key  --trace <proc_dir> [--out priv.pem]
  decrypt      --in <enc_dir> --trace <proc_dir> --out <dir> [--ext .EXT] [--mode auto|continuous|view|intermittent]
  decrypt-one  <file>          --trace <proc_dir> --out <dir> [--mode ...]
"""
import os, sys, glob, struct, argparse, hashlib
from math import gcd

VIEW  = 0x80000          # 512 KiB memory-mapped view
GAP   = 5                # plaintext bytes left at each view boundary (measured)
IBLK  = 0x100000         # 1 MiB encrypted block for the intermittent (very-large-file) tier
MAGIC = b"RISEN\x00"
MASK  = 0xffffffff


# ----------------------------- ChaCha8 (Bernstein layout) -----------------------------
def _rotl(x, c): return ((x << c) & MASK) | (x >> (32 - c))

def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & MASK; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & MASK; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & MASK; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & MASK; s[b] = _rotl(s[b] ^ s[c], 7)

def _chacha8_block(key32, nonce8, counter):
    s = list(struct.unpack("<4I", b"expand 32-byte k")) + list(struct.unpack("<8I", key32))
    s += list(struct.unpack("<2I", struct.pack("<Q", counter))) + list(struct.unpack("<2I", nonce8))
    w = s[:]
    for _ in range(4):                       # 8 rounds = 4 double-rounds
        _qr(w, 0, 4, 8, 12); _qr(w, 1, 5, 9, 13); _qr(w, 2, 6, 10, 14); _qr(w, 3, 7, 11, 15)
        _qr(w, 0, 5, 10, 15); _qr(w, 1, 6, 11, 12); _qr(w, 2, 7, 8, 13); _qr(w, 3, 4, 9, 14)
    return b"".join(struct.pack("<I", (w[i] + s[i]) & MASK) for i in range(16))

def chacha8_keystream(key32, nonce8, length, counter=0):
    out = bytearray()
    while len(out) < length:
        out += _chacha8_block(key32, nonce8, counter); counter += 1
    return bytes(out[:length])


# ----------------------------- RSA private key recovery -----------------------------
def _parse_privblob(d, off):
    """Parse a CryptoAPI PRIVATEKEYBLOB where d[off:off+4]=='RSA2'. Validate N == p*q."""
    if off < 8 or d[off - 8] != 0x07:
        return None
    bl = int.from_bytes(d[off + 4:off + 8], "little")
    if bl not in (1024, 2048, 4096):
        return None
    e = int.from_bytes(d[off + 8:off + 12], "little")
    if e < 3 or e % 2 == 0:
        return None
    nb, h = bl // 8, bl // 16
    p0 = off + 12
    if p0 + nb + 2 * h > len(d):
        return None
    n = int.from_bytes(d[p0:p0 + nb], "little"); p0 += nb
    p = int.from_bytes(d[p0:p0 + h], "little"); p0 += h
    q = int.from_bytes(d[p0:p0 + h], "little")
    if p <= 1 or q <= 1 or p * q != n:        # decisive check
        return None
    lam = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
    try:
        dd = pow(e, -1, lam)
    except ValueError:
        return None
    return (n, e, dd, p, q, bl)

def recover_priv_from_trace(proc_dir):
    for fn in sorted(glob.glob(os.path.join(proc_dir, "crypto_*.bin"))):
        d = open(fn, "rb").read()
        i = d.find(b"RSA2")
        while i >= 0:
            k = _parse_privblob(d, i)
            if k:
                return k, os.path.basename(fn)
            i = d.find(b"RSA2", i + 1)
    return None, None


# ----------------------------- file decryption -----------------------------
def _rsa_unwrap(key, blk):
    n, e, dd = key[0], key[1], key[2]
    c = int.from_bytes(blk[::-1], "big")      # CryptoAPI stores RSA ciphertext little-endian
    if c >= n:
        return None
    m = pow(c, dd, n).to_bytes(len(blk), "big")
    if m[:2] != b"\x00\x02":                  # PKCS#1 v1.5
        return None
    j = m.find(b"\x00", 2)
    return m[j + 1:] if j >= 0 else None

def _intermittent_layout(total):
    """Encrypted-block layout for the very-large-file tier: 1 MiB blocks evenly spaced so the first
    starts at 0 and the last ends at EOF. Returns list of (start, length) encrypted spans.
    NB: block COUNT/spacing is build-specific; this reproduces the analysed sample. Tune if needed."""
    if total <= 2 * IBLK:
        return [(0, total)]
    nblocks = max(2, round(total / (IBLK + 8362326)) + 1)   # measured cadence on the analysed build
    if nblocks < 2:
        nblocks = 2
    span = (total - IBLK) // (nblocks - 1)
    return [(i * span, IBLK) for i in range(nblocks)]

def decrypt_blob(enc_bytes, key, mode="auto"):
    """Return recovered plaintext. mode: continuous | view | intermittent | auto."""
    nb = key[5] // 8
    ridx = enc_bytes.rfind(MAGIC)
    if ridx < 0:
        raise ValueError("no RISEN footer marker (not a BlackHunt file?)")
    payload = _rsa_unwrap(key, enc_bytes[ridx + 6: ridx + 6 + nb])
    if not payload or len(payload) < 40:
        raise ValueError("RSA unwrap failed (wrong private key for this file)")
    ck, cn = payload[:32], payload[32:40]
    body = enc_bytes[:ridx]
    n = len(body)

    if mode == "auto":
        if n <= VIEW:
            mode = "continuous"          # single mapped view: fully continuous
        elif n > 4 * IBLK:
            mode = "intermittent"        # very large: 1 MiB blocks + plaintext gaps
        else:
            mode = "view"                # small/medium multi-view: 512 KiB views + boundary gap

    if mode == "continuous":
        ks = chacha8_keystream(ck, cn, n)
        return bytes(a ^ b for a, b in zip(body, ks))

    if mode == "view":
        ks = chacha8_keystream(ck, cn, n)
        out = bytearray(n); bpos = kpos = 0
        while bpos < n:
            take = min(VIEW, n - bpos)
            for i in range(take):
                out[bpos + i] = body[bpos + i] ^ ks[kpos + i]
            bpos += take; kpos += take
            if bpos >= n:
                break
            g = min(GAP, n - bpos)
            out[bpos:bpos + g] = body[bpos:bpos + g]    # plaintext gap; keystream not advanced
            bpos += g
        return bytes(out)

    if mode == "intermittent":
        spans = _intermittent_layout(n)
        ks = chacha8_keystream(ck, cn, sum(l for _, l in spans) + 64)
        out = bytearray(body); kpos = 0
        for (st, ln) in spans:
            ln = min(ln, n - st)
            for x in range(ln):
                out[st + x] = body[st + x] ^ ks[kpos + x]
            kpos += ln
        return bytes(out)                                # plaintext gaps left as-is

    raise ValueError("unknown mode")


# ----------------------------- CLI -----------------------------
def _load_key(args):
    if getattr(args, "key", None):
        from Crypto.PublicKey import RSA
        r = RSA.import_key(open(args.key, "rb").read())
        return (r.n, r.e, r.d, r.p, r.q, r.size_in_bits())
    if not getattr(args, "trace", None):
        sys.exit("[-] supply --trace <proc_dir> or --key <priv.pem>")
    k, src = recover_priv_from_trace(args.trace)
    if not k:
        sys.exit("[-] could not recover an RSA private key from the trace")
    print(f"[+] recovered RSA-{k[5]} victim private key from {src} (N == p*q verified)")
    return k

def _basename(path, ext):
    b = os.path.basename(path)
    if ".[" in b:
        return b[:b.find(".[")]
    return b[:-len(ext)] if ext and b.endswith(ext) else b

def cmd_recover_key(args):
    k = _load_key(args)
    if args.out:
        from Crypto.PublicKey import RSA
        open(args.out, "wb").write(RSA.construct((k[0], k[1], k[2], k[3], k[4])).export_key())
        print(f"[+] wrote private key -> {args.out}")

def cmd_decrypt(args):
    k = _load_key(args)
    os.makedirs(args.out, exist_ok=True)
    files = sorted(glob.glob(os.path.join(args.indir, "*" + args.ext)))
    ok = 0
    for f in files:
        base = _basename(f, args.ext)
        try:
            dec = decrypt_blob(open(f, "rb").read(), k, args.mode)
            open(os.path.join(args.out, base), "wb").write(dec)
            print(f"  [OK] {base}  ({len(dec)} B, sha256={hashlib.sha256(dec).hexdigest()[:16]})")
            ok += 1
        except Exception as ex:
            print(f"  [--] {base}: {ex}")
    print(f"\n[+] decrypted {ok}/{len(files)} files -> {args.out}  (mode={args.mode})")

def cmd_decrypt_one(args):
    k = _load_key(args)
    os.makedirs(args.out, exist_ok=True)
    base = _basename(args.file, "")
    dec = decrypt_blob(open(args.file, "rb").read(), k, args.mode)
    open(os.path.join(args.out, base), "wb").write(dec)
    print(f"[+] {base}: {len(dec)} B  sha256={hashlib.sha256(dec).hexdigest()}")

def main():
    ap = argparse.ArgumentParser(description="BlackHunt ransomware recovery")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("recover-key"); a.add_argument("--trace"); a.add_argument("--key"); a.add_argument("--out")
    a.set_defaults(func=cmd_recover_key)
    b = sub.add_parser("decrypt"); b.add_argument("--in", dest="indir", required=True)
    b.add_argument("--trace"); b.add_argument("--key"); b.add_argument("--out", required=True)
    b.add_argument("--ext", default=".LJB8BD3WND")
    b.add_argument("--mode", default="auto", choices=["auto", "continuous", "view", "intermittent"])
    b.set_defaults(func=cmd_decrypt)
    c = sub.add_parser("decrypt-one"); c.add_argument("file"); c.add_argument("--trace")
    c.add_argument("--key"); c.add_argument("--out", required=True)
    c.add_argument("--mode", default="auto", choices=["auto", "continuous", "view", "intermittent"])
    c.set_defaults(func=cmd_decrypt_one)
    args = ap.parse_args()
    args.func(args)

if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    main()
