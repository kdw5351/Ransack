#!/usr/bin/env python3
"""wannacry_recover — key-recovery decryption of WannaCry (`.WNCRY`) victim files.

WannaCry generates a per-victim RSA-2048 keypair at runtime; each file is encrypted with a fresh
AES-128 key that is wrapped with the victim RSA *public* key and stored in the file header. The
victim RSA *private* key is itself wrapped with the operator's master public key (so only the
operator can normally decrypt it) — but the plaintext private key transits the CSP at key-birth /
`CryptExportKey`, and (pre-Win10, or under instrumentation) lingers in process memory. The Ransack
analyzer captures that key-birth buffer (`crypto_<seq>.bin`).

This tool reconstructs the victim RSA private key from that captured key material, then — exactly as
Guinet's *wannakey* / Delpy & Suiche's *wanakiwi* do once the key is in hand — unwraps each file's
RSA-wrapped AES-128 key and AES-128-CBC-decrypts the body. With the private key, **every** file the
victim's public key wrapped is recoverable (universal for that victim run).

Recovery class (this is the project's third mechanism — key recovery, distinct from brute-force and
plaintext-residue):
  - key brute-force      (hdlocker)            : recover a weak KEY by brute force, then decrypt.
  - plaintext residue    (razrusheniye, makop) : capture the plaintext at the encrypt sink; no key.
  - key recovery (RSA)   (wannacry)            : reconstruct the in-memory victim RSA private key,
                                                 then unwrap each file's AES key (wanakiwi class).

Subcommands:
  recover-key <proc_dir> [out.pem]            reconstruct the victim RSA private key from the trace
                                              (validated by N == p*q) and write it as PEM
  decrypt     <proc_dir> <enc_dir> [out_dir]  recover the key, then decrypt every *.WNCRY in enc_dir

Required input: a trace proc dir whose key-residue dump (crypto_*.bin) holds the victim
PRIVATEKEYBLOB, and the matching `.WNCRY` files from the SAME run (the keypair is per-run).
No internet, no payment; Python 3.10+ with pycryptodome.

.WNCRY file format:
  [8]  "WANACRY!"                 magic
  [4]  keylen (= 0x100)           wrapped-key length
  [N]  RSA-encrypted AES key      CryptoAPI CryptEncrypt output (little-endian byte order)
  [4]  flag
  [8]  original file size (u64)
  [..] AES-128-CBC(key, IV=0) ciphertext (padded to 16 B; trim to original size)
"""
import os, sys, glob, struct
from math import gcd


# ── RSA private-key reconstruction from the captured CryptoAPI PRIVATEKEYBLOB ─────────────────────────
def _parse_privblob(d, off):
    """`off` indexes the 'RSA2' magic. CryptoAPI PRIVATEKEYBLOB fields are little-endian.
    BLOBHEADER(bType=0x07 PRIVATEKEYBLOB) | RSAPUBKEY('RSA2', bitlen, pubexp) | modulus | p | q | ...
    Returns (n, e, d, p, q) or None. Validated by N == p*q (decisive)."""
    if off < 8 or d[off - 8] != 0x07:          # bType must be PRIVATEKEYBLOB
        return None
    bitlen = int.from_bytes(d[off + 4:off + 8], "little")
    if bitlen not in (1024, 2048, 4096):
        return None
    e = int.from_bytes(d[off + 8:off + 12], "little")
    if e < 3:                                   # reject degenerate exponents (e.g. e=1)
        return None
    nb, half = bitlen // 8, bitlen // 16
    p0 = off + 12
    if p0 + nb + 2 * half > len(d):
        return None
    n = int.from_bytes(d[p0:p0 + nb], "little"); p0 += nb
    p = int.from_bytes(d[p0:p0 + half], "little"); p0 += half
    q = int.from_bytes(d[p0:p0 + half], "little")
    if p <= 1 or q <= 1 or p * q != n:          # decisive validity check
        return None
    lam = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
    try:
        dexp = pow(e, -1, lam)
    except Exception:
        return None
    return (n, e, dexp, p, q)


def recover_key(proc_dir):
    """Scan the key-residue dump for a valid victim RSA private key."""
    for fn in sorted(glob.glob(os.path.join(proc_dir, "crypto_*.bin"))):
        try:
            d = open(fn, "rb").read()
        except OSError:
            continue
        i = d.find(b"RSA2")
        while i >= 0:
            k = _parse_privblob(d, i)
            if k:
                return k, os.path.basename(fn)
            i = d.find(b"RSA2", i + 1)
    return None, None


MAGICS = [(b"\xff\xd8\xff", "jpg"), (b"%PDF", "pdf"), (b"PK\x03\x04", "zip/ooxml"),
          (b"\xd0\xcf\x11\xe0", "ole"), (b"\x89PNG", "png"), (b"{\\rtf", "rtf"),
          (b"\x1f\x8b", "gz"), (b"BM", "bmp")]


def _kind(b):
    for m, name in MAGICS:
        if b.startswith(m):
            return name
    pr = sum(1 for x in b[:128] if 9 <= x <= 13 or 32 <= x < 127)
    return "text" if pr >= 115 else "data"


def cmd_recover_key(proc_dir, out_pem=None):
    from Crypto.PublicKey import RSA
    k, src = recover_key(proc_dir)
    if not k:
        sys.exit("[!] no valid victim RSA private key (PRIVATEKEYBLOB, N==p*q) in this trace")
    n, e, d, p, q = k
    rsa = RSA.construct((n, e, d, p, q))
    out_pem = out_pem or os.path.join(proc_dir, "wannacry_victim_private.pem")
    open(out_pem, "wb").write(rsa.export_key())
    print(f"[+] recovered RSA-{n.bit_length()} victim private key from {src} (N==p*q, e={e})")
    print(f"[+] wrote {out_pem}")


def cmd_decrypt(proc_dir, enc_dir, out_dir=None):
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import AES, PKCS1_v1_5
    k, src = recover_key(proc_dir)
    if not k:
        sys.exit("[!] no valid victim RSA private key in this trace")
    n, e, d, p, q = k
    rsa = RSA.construct((n, e, d, p, q))
    unwrap = PKCS1_v1_5.new(rsa)
    out_dir = out_dir or os.path.join(enc_dir, "recovered")
    os.makedirs(out_dir, exist_ok=True)
    print(f"[+] recovered RSA-{n.bit_length()} private key from {src}")
    files = sorted(glob.glob(os.path.join(enc_dir, "*.WNCRY")))
    print(f"[+] {len(files)} .WNCRY files -> {out_dir}\n")
    ok = 0
    for f in files:
        b = open(f, "rb").read()
        name = os.path.basename(f)[:-6]
        if b[:8] != b"WANACRY!":
            print(f"  {name:28s} skip (not WANACRY! header)"); continue
        keylen = struct.unpack("<I", b[8:12])[0]
        enckey = b[12:12 + keylen]
        fsize = struct.unpack("<Q", b[16 + keylen:24 + keylen])[0]
        body = b[24 + keylen:]
        # CryptoAPI CryptEncrypt output is little-endian: reverse to big-endian, then PKCS#1 v1.5 unwrap
        aeskey = unwrap.decrypt(enckey[::-1], None)
        if not aeskey or len(aeskey) not in (16, 24, 32):
            aeskey = unwrap.decrypt(enckey, None)
        if not aeskey or len(aeskey) not in (16, 24, 32):
            print(f"  {name:28s} RSA unwrap failed"); continue
        pt = AES.new(aeskey, AES.MODE_CBC, bytes(16)).decrypt(body[:len(body) // 16 * 16])
        if 0 < fsize <= len(pt):
            pt = pt[:fsize]
        open(os.path.join(out_dir, name), "wb").write(pt)
        ok += 1
        print(f"  {name:28s} aes={aeskey.hex()}  {len(pt)}B  -> {_kind(pt)}")
    print(f"\n[+] decrypted {ok}/{len(files)} files with the recovered key (no ransom paid)")


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__); sys.exit(0)
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "recover-key":
        cmd_recover_key(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
    elif cmd == "decrypt" and len(sys.argv) >= 4:
        cmd_decrypt(sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else None)
    else:
        print(__doc__); sys.exit(1)


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    main()
