#!/usr/bin/env python3
"""
NitroRansomware recovery (build-fixed password -> PBKDF2; universal, offline).

Scheme (reverse-engineered + verified byte-exact):
  - Each encrypted file is `[32-byte PBKDF2 salt][AES-256-CBC ciphertext, PKCS#7]`, renamed
    `<original>.givemenitro`. There is no trailer.
  - key + IV are derived with .NET `Rfc2898DeriveBytes` (PBKDF2-HMAC-SHA1) over a **build-fixed
    password** and the file's own random salt, 50,000 iterations:
        stream = PBKDF2-HMAC-SHA1(password = b"ZGVmYXVsdHBhc3N3b3Jk", salt = file[0:32], iters = 50000)
        key = stream.GetBytes(32)   # AES-256 key
        iv  = stream.GetBytes(16)   # next 16 bytes of the SAME stream
  - `ZGVmYXVsdHBhc3N3b3Jk` is base64 of the ASCII word `defaultpassword`.

Why recoverable: the password is **build-fixed** (a compiled-in constant), and the only per-file
randomness (the salt) is stored in the clear at the head of every encrypted file. So one password
recovers every file of the build, with no key in memory to capture and no payment -- the *build-fixed
key derivation* recovery class (cf. Crypt888, HDLocker).

Dynamic-analysis contribution: NitroRansomware is .NET / managed crypto, so the final AES key is not a
clean buffer in the trace. But the PBKDF2 HMAC-SHA1 *inner pads* are: the ipad (secret XOR 0x36) and
opad (secret XOR 0x5c) are captured in `crypto_25` / `crypto_85` (ipad) and `crypto_61` (opad). Folding
either pad back recovers the 20-byte HMAC key = the static password. `recover-key --trace` does exactly
that, and falls back to printing the known constant.

Usage:
  python nitro_recover.py recover-key [--trace <trace_dir>]
  python nitro_recover.py decrypt --in <enc_dir> --out <dir> [--ext .givemenitro]
                                  [--known-size <originals_dir>] [--password <ascii>]
"""
import os, sys, glob, argparse, hashlib

# build-fixed password (base64 of "defaultpassword"); the ASCII string is fed to Rfc2898DeriveBytes verbatim
PASSWORD = b"ZGVmYXVsdHBhc3N3b3Jk"
SALT_LEN = 32
ITERS    = 50000
EXT      = ".givemenitro"

# file-type signatures used as a "did this decrypt correctly?" oracle (no original needed)
MAGICS = [b"PK\x03\x04", b"%PDF", b"\x89PNG\r\n\x1a\n", b"MZ", b"\xd0\xcf\x11\xe0",
          b"7z\xbc\xaf", b"Rar!\x1a\x07", b"\x1f\x8b", b"\xff\xd8\xff", b"ID3", b"RIFF",
          b"\x00\x00\x00\x18ftyp", b"\x1aE\xdf\xa3", b"\xef\xbb\xbf", b"L\x00\x00\x00"]


def derive(password, salt):
    """key(32) || iv(16) from one PBKDF2-HMAC-SHA1 stream, exactly as Rfc2898DeriveBytes.GetBytes."""
    dk = hashlib.pbkdf2_hmac("sha1", password, salt, ITERS, 48)
    return dk[:32], dk[32:48]


def _unpad(b):
    if not b:
        return b
    n = b[-1]
    return b[:-n] if 1 <= n <= 16 and b[-n:] == bytes([n]) * n else b


def decrypt_blob(raw, password):
    """raw = [32B salt][AES-256-CBC ciphertext, PKCS#7]."""
    from Crypto.Cipher import AES
    salt = raw[:SALT_LEN]
    key, iv = derive(password, salt)
    ct = raw[SALT_LEN:]
    nb = len(ct) // 16
    return _unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct[:nb * 16]))


def _looks_recovered(pt):
    if not pt:
        return False
    if any(pt.startswith(m) for m in MAGICS):
        return True
    # printable text (allow tab/newline/CR), sampled over the head
    return all((9 <= b < 127) or b in (9, 10, 13) for b in pt[:64])


def fold_password_from_trace(trace_dir):
    """Best-effort: recover the 20-byte HMAC key (= the password) from captured PBKDF2 inner pads.

    PBKDF2-HMAC-SHA1 forms two 64-byte blocks per HMAC: ipad = key_padded XOR 0x36, opad = key_padded
    XOR 0x5c. A captured block whose tail is a run of 0x36 (ipad) or 0x5c (opad) yields the key in its
    leading non-pad bytes. We try both and return the ASCII password if both agree (or either decodes).
    """
    import base64
    blobs = sorted(glob.glob(os.path.join(trace_dir, "**", "crypto_*.bin"), recursive=True))
    cands = {}
    for f in blobs:
        b = open(f, "rb").read()
        if len(b) < 21:
            continue
        for pad, name in ((0x36, "ipad"), (0x5c, "opad")):
            # find the longest trailing run of the pad byte; the key is what precedes it
            tail = len(b)
            while tail > 0 and b[tail - 1] == pad:
                tail -= 1
            if tail == len(b) or tail == 0:
                continue
            klen = tail
            if not (1 <= klen <= 20):
                continue
            key = bytes(x ^ pad for x in b[:klen])
            if all(32 <= c < 127 for c in key):  # printable -> plausible ASCII password
                cands.setdefault(key, set()).add(name)
    for key, seen in cands.items():
        try:
            base64.b64decode(key, validate=True)
        except Exception:
            decoded = None
        else:
            decoded = base64.b64decode(key)
        if key == PASSWORD or len(seen) >= 2:
            return key, sorted(seen), decoded
    # nothing folded cleanly
    return None, [], None


def main():
    ap = argparse.ArgumentParser(description="NitroRansomware recovery (AES-256-CBC, PBKDF2, build-fixed password)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    rk = sub.add_parser("recover-key", help="print the static password (optionally fold it from a trace)")
    rk.add_argument("--trace", help="trace dir (proc_<pid>/ or its parent) to fold the HMAC pads from")

    d = sub.add_parser("decrypt", help="decrypt every encrypted file in a directory")
    d.add_argument("--in", dest="indir", required=True)
    d.add_argument("--out", required=True)
    d.add_argument("--ext", default=EXT, help=f"encrypted extension (default: {EXT})")
    d.add_argument("--known-size", dest="known", help="dir of original files for a byte-exact SHA-256 check")
    d.add_argument("--password", help="override the build-fixed password (ASCII)")
    a = ap.parse_args()

    if a.cmd == "recover-key":
        if a.trace:
            key, seen, decoded = fold_password_from_trace(a.trace)
            if key:
                print(f"[+] folded from trace HMAC pads ({', '.join(seen)}): {key.decode('latin-1')}")
                if decoded is not None:
                    print(f"    base64 -> {decoded.decode('latin-1')!r}")
                print(f"    (this is the build-fixed Rfc2898DeriveBytes password; one password decrypts every file)")
                return
            print("[-] could not fold a password from the trace; falling back to the known constant")
        print(f"[+] password = {PASSWORD.decode()}   (base64 of \"defaultpassword\")")
        print(f"    key||iv  = Rfc2898DeriveBytes(password, salt=file[0:32], iters={ITERS}).GetBytes(32)+GetBytes(16)")
        print(f"    (build-fixed / compiled into the binary; one password decrypts every victim of the build)")
        return

    password = a.password.encode() if a.password else PASSWORD
    files = sorted(f for f in glob.glob(os.path.join(a.indir, "*")) if f.endswith(a.ext))
    if not files:
        sys.exit(f"[-] no encrypted files (*{a.ext}) in {a.indir}")

    originals = {}
    if a.known:
        for f in glob.glob(os.path.join(a.known, "*")):
            if os.path.isfile(f):
                originals[os.path.basename(f)] = f

    os.makedirs(a.out, exist_ok=True)
    ok = valid = exact = checked = skipped = 0
    for f in files:
        base = os.path.basename(f)
        out_name = base[:-len(a.ext)] if base.endswith(a.ext) else base
        raw = open(f, "rb").read()
        if len(raw) < SALT_LEN + 16:
            skipped += 1
            print(f"  SKIP (empty/{len(raw)}B) {out_name}")
            continue
        pt = decrypt_blob(raw, password)
        open(os.path.join(a.out, out_name), "wb").write(pt)
        ok += 1
        sig = _looks_recovered(pt)
        valid += bool(sig)
        tag = "OK" if sig else "??"
        extra = ""
        if out_name in originals:
            checked += 1
            want = hashlib.sha256(open(originals[out_name], "rb").read()).hexdigest()
            got = hashlib.sha256(pt).hexdigest()
            if want == got:
                exact += 1
                extra = " [byte-exact]"
            else:
                extra = f" [MISMATCH sha256={got[:16]}]"
        print(f"  {tag} {out_name:<40} {pt[:8].hex()} ({len(pt)} B){extra}")

    print(f"\n[+] {ok} files decrypted -> {a.out}   ({valid}/{ok} valid file signature, {skipped} empty skipped)")
    if a.known:
        print(f"[+] byte-exact: {exact}/{checked} checked against originals in {a.known}")


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    main()
