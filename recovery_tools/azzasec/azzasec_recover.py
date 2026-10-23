#!/usr/bin/env python3
"""
AzzaSec ransomware recovery (AES-256-CBC; key+IV both derived from a captured password via SHA-512).

Scheme (reverse-engineered + verified byte-exact):
  - **AES-256-CBC + PKCS#7**, whole-file. A SINGLE (key, IV) pair encrypts **every** file in the run.
  - The key material is derived from a per-run **password** with a single SHA-512:
        digest = SHA512(password)
        AES-256 key = digest[:32]
        IV          = digest[32:48]
    (matches the public reporting that AzzaSec "uses AES and SHA-512 to generate keys and IVs".)
  - The password is a 20-char random ASCII string generated at runtime (CryptGenRandom /
    SystemFunction036). The attacker RSA-wraps it for the operator, so a victim cannot read it back —
    BUT the Ransack trace captures the plaintext password buffer (a `crypto_<seq>.bin` snapshot) the
    moment it is materialised in memory, before it is wrapped. One captured password decrypts the
    whole infection.
  - **Encrypted-file layout**: `<name>.AzzaSec` = `[ciphertext]` only (no header/footer; size is the
    PKCS#7-padded plaintext length). The machine-derived seeds also present in the trace (the network
    MAC as a 24-byte ASCII blob, and a 91-byte machine fingerprint) are NOT the file-key seed — only
    the 20-char random password is (verified: only its SHA-512 reproduces the plaintext).

Recovery class: captured symmetric key material (cf. PayBreak; RC-07). The password is otherwise
RSA-protected to the operator, so this recovers an infection only when the password was captured at
encryption time (which is exactly what the Ransack PinTool does).

Usage:
  python azzasec_recover.py recover-key --trace <proc_dir> --in <enc_dir>
  python azzasec_recover.py decrypt --in <enc_dir> --trace <proc_dir> --out <dir> [--known-size <orig_dir>]
  python azzasec_recover.py decrypt --in <enc_dir> --password <str> --out <dir>
  python azzasec_recover.py decrypt --in <enc_dir> --key <hex> --iv <hex> --out <dir>
"""
import os, sys, glob, argparse, hashlib

EXT = ".AzzaSec"

# known file-type magics (first plaintext bytes) used only to *report* a recognisable recovery;
# key validation does not depend on them (PKCS#7 across all files is the deterministic check).
MAGICS = [b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"%PDF", b"PK\x03\x04",
          b"7z\xbc\xaf\x27\x1c", b"\x1f\x8b\x08", b"Rar!\x1a\x07", b"GIF8", b"ID3", b"BM",
          b"MZ", b"\x25\x21PS", b"{\\rtf", b"<?xml", b"BAIT"]


def _aes_cbc(key, iv):
    from Crypto.Cipher import AES
    return AES.new(key, AES.MODE_CBC, iv)


def _aes_ecb(key):
    from Crypto.Cipher import AES
    return AES.new(key, AES.MODE_ECB)


def kdf(password: bytes):
    """AzzaSec key schedule: one SHA-512 over the password -> AES-256 key + 16-byte IV."""
    d = hashlib.sha512(password).digest()
    return d[:32], d[32:48]


def _unpad(d: bytes) -> bytes:
    if d and 1 <= d[-1] <= 16 and d[-d[-1]:] == bytes([d[-1]]) * d[-1]:
        return d[:-d[-1]]
    return d


def _pkcs7_ok_lastblock(ct: bytes, key: bytes) -> bool:
    """Decrypt only the last CBC block and check PKCS#7 validity (cheap, IV-independent for the
    last block). A wrong key gives valid padding by chance < ~0.4 %/file, so 'valid on every file'
    is decisive."""
    if len(ct) < 32 or len(ct) % 16:
        return False
    last = _aes_ecb(key).decrypt(ct[-16:])
    prev = ct[-32:-16]
    pt = bytes(last[i] ^ prev[i] for i in range(16))
    n = pt[-1]
    return 1 <= n <= 16 and pt[-n:] == bytes([n]) * n


def _candidate_passwords(proc_dir):
    """Yield distinct password candidates captured in the trace: each whole crypto bin, plus every
    maximal printable-ASCII run inside a bin (the password is such a run). Deterministic, no guessing —
    each candidate is validated by decrypting real ciphertext."""
    seen = set()
    for fn in sorted(glob.glob(os.path.join(proc_dir, "crypto_*.bin"))):
        try:
            b = open(fn, "rb").read()
        except OSError:
            continue
        if b and b not in seen:
            seen.add(b)
            yield b
        run = bytearray()
        for x in b + b"\x00":
            if 33 <= x <= 126:
                run.append(x)
            else:
                if 8 <= len(run) <= 64 and bytes(run) not in seen:
                    seen.add(bytes(run))
                    yield bytes(run)
                run = bytearray()


def find_password(enc_dir, proc_dir):
    """Recover (password, key, IV) from the trace by deriving SHA-512 key material for each captured
    candidate and validating it against the actual ciphertext (PKCS#7 on every file + >=2 known
    magics). Returns (password, key, iv) or None."""
    files = sorted(glob.glob(os.path.join(enc_dir, "*" + EXT)))
    cts = []
    for f in files:
        try:
            cts.append(open(f, "rb").read())
        except OSError:
            pass
    cts = [c for c in cts if len(c) >= 32 and len(c) % 16 == 0]
    if not cts:
        return None
    for p in _candidate_passwords(proc_dir):
        key, iv = kdf(p)
        try:
            if not all(_pkcs7_ok_lastblock(c, key) for c in cts):
                continue
        except ValueError:
            continue
        magics = 0
        for c in cts:
            head = _aes_cbc(key, iv).decrypt(c[:16])
            if any(head.startswith(m) for m in MAGICS):
                magics += 1
        if magics >= 2:
            return p, key, iv
    return None


def decrypt_file(enc_path, key, iv, out_path, known_size_dir=None):
    ct = open(enc_path, "rb").read()
    if len(ct) % 16:
        ct = ct[:len(ct) // 16 * 16]
    pt = _unpad(_aes_cbc(key, iv).decrypt(ct))
    open(out_path, "wb").write(pt)
    if known_size_dir:
        base = os.path.basename(out_path)
        op = os.path.join(known_size_dir, base)
        if os.path.isfile(op):
            orig = open(op, "rb").read()
            return pt == orig, f"{len(pt)}B byte-exact={pt == orig}"
    return True, f"{len(pt)}B"


def main():
    ap = argparse.ArgumentParser(description="AzzaSec recovery (AES-256-CBC, key/IV = SHA-512(captured password))")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("recover-key")
    a.add_argument("--in", dest="indir", required=True)
    a.add_argument("--trace", required=True)
    b = sub.add_parser("decrypt")
    b.add_argument("--in", dest="indir", required=True)
    b.add_argument("--trace")
    b.add_argument("--password")
    b.add_argument("--key")
    b.add_argument("--iv")
    b.add_argument("--out", required=True)
    b.add_argument("--known-size", dest="known", help="[validation] dir of original files -> byte-exact check")
    args = ap.parse_args()

    if args.cmd == "recover-key":
        r = find_password(args.indir, args.trace)
        if r:
            p, key, iv = r
            try:
                ps = p.decode("ascii")
            except Exception:
                ps = p.hex()
            print(f"[+] password : {ps}")
            print(f"[+] AES-256 key: {key.hex()}")
            print(f"[+] IV         : {iv.hex()}")
        else:
            print("[-] password not found in trace")
        return

    if args.password is not None:
        key, iv = kdf(args.password.encode())
    elif args.key and args.iv:
        key, iv = bytes.fromhex(args.key), bytes.fromhex(args.iv)
    else:
        r = find_password(args.indir, args.trace) if args.trace else None
        if not r:
            sys.exit("[-] could not recover key (give --trace <proc_dir>, --password <str>, or --key/--iv)")
        _, key, iv = r
    print(f"[+] AES-256 key: {key.hex()}  IV: {iv.hex()}")
    os.makedirs(args.out, exist_ok=True)
    files = sorted(glob.glob(os.path.join(args.indir, "*" + EXT)))
    ok = exact = 0
    for f in files:
        base = os.path.basename(f)[:-len(EXT)]
        try:
            good, info = decrypt_file(f, key, iv, os.path.join(args.out, base), args.known)
            print(f"  [OK] {base}: {info}")
            ok += 1
            exact += int("byte-exact=True" in info)
        except Exception as e:
            print(f"  [!!] {base}: {e}")
    tail = f"  ({exact} byte-exact vs originals)" if args.known else ""
    print(f"\n[+] {ok}/{len(files)} written -> {args.out}{tail}")


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    main()
