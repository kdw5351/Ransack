#!/usr/bin/env python3
"""
Everbe ransomware recovery (captured AES-256 key + per-file IV from a known header).

Scheme (reverse-engineered + verified byte-exact):
  - **AES-256-CBC** with a SINGLE 32-byte key **reused for every file** in the run. The key is
    generated once, materialised in process memory, and captured by the Ransack trace (a raw key
    buffer in `crypto_<seq>.bin`). One captured key decrypts the whole infection.
  - **Per-file random IV** (16 B). The IV is *not* reused and is wrapped (with the AES key) under the
    operator's RSA-2048 public key into the file footer — so it cannot be read back directly. But CBC
    only mixes the IV into the **first 16-byte block**, and the IV is *recovered from known plaintext*:
        IV = AES_ECB_decrypt(key, C0) XOR P0
    where P0 is the first 16 bytes of the original — available for any file whose type has a fixed
    header (PNG/PDF/ZIP/JPEG/GZIP/7z/RAR/Office/...). The remaining blocks need no IV.
  - **Encrypted-file layout**: `<name>.[<id>].eV3rbe` = `[ciphertext][~544-byte footer]`. The footer is
    `[per-file binary prefix][fixed 512-char hex = RSA-wrapped (key,IV), identical across files]`.
  - **Partial encryption for large files**: files up to ~1 MiB are fully AES-CBC encrypted; files larger
    than ~1 MiB are encrypted in the first ~1 MiB chunk only (the rest is a separate chunked region) —
    so for >1 MiB files this tool recovers the first ~1 MiB byte-exact.

Recovery class: captured symmetric session key (cf. PayBreak; RC-07) + known-plaintext IV recovery.

Usage:
  python everbe_recover.py recover-key --in <enc_dir> --trace <proc_dir>
  python everbe_recover.py decrypt     --in <enc_dir> --trace <proc_dir> --out <dir>
  python everbe_recover.py decrypt     --in <enc_dir> --key <hex> --out <dir> [--known-size <orig_dir>]
"""
import os, sys, glob, argparse

EXT = ".eV3rbe"
FOOTER_MAX = 544          # footer is 512..544 B; strip conservatively then 16-align
CAP = 1 << 20             # ~1 MiB: encryption cap for large files

# original-extension -> a known plaintext prefix (>=16 B preferred, for a full IV)
HEADERS = {
    ".png":  b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
    ".pdf":  b"%PDF-1.",
    ".zip":  b"PK\x03\x04", ".docx": b"PK\x03\x04", ".xlsx": b"PK\x03\x04",
    ".pptx": b"PK\x03\x04", ".jar": b"PK\x03\x04",
    ".jpg":  b"\xff\xd8\xff", ".jpeg": b"\xff\xd8\xff",
    ".gz":   b"\x1f\x8b\x08", ".7z": b"7z\xbc\xaf\x27\x1c", ".rar": b"Rar!\x1a\x07",
    ".gif":  b"GIF8", ".mp3": b"ID3", ".pdf2": b"%PDF",
}
_ANY = [b"\x89PNG\r\n\x1a\n", b"%PDF", b"PK\x03\x04", b"\xff\xd8\xff", b"\x1f\x8b\x08",
        b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07", b"GIF8", b"ID3", b"\xef\xbb\xbf"]


def _aes(key, mode, iv=None):
    from Crypto.Cipher import AES
    return AES.new(key, AES.MODE_ECB) if mode == "ecb" else AES.new(key, AES.MODE_CBC, iv)


def _orig_ext(enc_name):
    base = enc_name
    i = base.find(".[")               # strip ".[<id>].eV3rbe"
    if i > 0:
        base = base[:i]
    return os.path.splitext(base)[1].lower(), base


def _looks_plain(block16):
    if any(block16.startswith(m) for m in _ANY):
        return True
    pr = sum(1 for b in block16 if 9 <= b <= 13 or 32 <= b <= 126)
    return pr >= 15


def _candidate_keys(proc_dir):
    seen = set()
    for fn in sorted(glob.glob(os.path.join(proc_dir, "crypto_*.bin"))):
        try:
            b = open(fn, "rb").read()
        except OSError:
            continue
        for off in range(0, max(1, len(b) - 31)):
            k = b[off:off + 32]
            if len(k) == 32 and k not in seen:
                seen.add(k)
                yield k


def _recover_iv(ct, key, known16):
    dec0 = _aes(key, "ecb").decrypt(ct[:16])
    return bytes(dec0[i] ^ known16[i] for i in range(min(16, len(known16)))) + b"\x00" * (16 - min(16, len(known16)))


def find_key(enc_dir, proc_dir):
    """Recover the AES key from the trace. NOTE: the IV is recovered from the header, which makes the
    FIRST block decrypt to that header for *any* key (tautology) — so the first block cannot validate the
    key. Instead validate on **blocks 1+**, which in CBC depend only on the key (not the IV): a wrong key
    yields random bytes there; the right key yields real plaintext. Anchor across several files."""
    files = sorted(glob.glob(os.path.join(enc_dir, "*" + EXT)))
    samples = [open(f, "rb").read()[:64] for f in files]
    samples = [b for b in samples if len(b) >= 48]
    if len(samples) < 2:
        return None

    def body_is_plain(c, k):
        # decrypt blocks 1-2 (bytes 16..48) with IV=0 (IV-independent for blocks>=1) and test plaintext
        p = _aes(k, "cbc", b"\x00" * 16).decrypt(c[:48])
        return _looks_plain(p[16:32]) or _looks_plain(p[32:48])

    for k in _candidate_keys(proc_dir):
        try:
            hits = sum(1 for c in samples if body_is_plain(c, k))
        except ValueError:
            continue
        # a wrong key yields ~0 printable bodies (random); even 3 hits is decisive (binary files
        # stay high-entropy even when correctly decrypted, so only text-ish files contribute).
        if hits >= 3:
            return k
    return None


def decrypt_file(enc_path, key, out_path, known_size_dir=None):
    d = open(enc_path, "rb").read()
    name = os.path.basename(enc_path)
    ext, base = _orig_ext(name)
    ct = d[:max(16, (len(d) - FOOTER_MAX) // 16 * 16)]   # strip footer, 16-align

    # P0 (first 16 plaintext bytes) for IV recovery: from --known-size original, else file-type header
    p0 = None
    if known_size_dir:
        op = os.path.join(known_size_dir, base)
        if os.path.isfile(op):
            orig = open(op, "rb").read()
            p0 = orig[:16]
            o = len(orig)
            n_enc = min(o, CAP)
            ct = d[:(n_enc + 15) // 16 * 16]
            iv = _recover_iv(ct, key, p0)
            dec = _aes(key, "cbc", iv).decrypt(ct)
            rec = dec[:n_enc] + d[len(ct):len(ct) + (o - n_enc)]   # +plaintext remainder for >1MiB
            open(out_path, "wb").write(rec[:o])
            return rec[:o] == orig, f"{len(rec[:o])}B byte-exact={rec[:o]==orig}"
    hdr = HEADERS.get(ext)
    if hdr:
        iv = _recover_iv(ct, key, hdr[:16])
    else:
        iv = b"\x00" * 16        # body still byte-exact; first block may be off without a header
    dec = _aes(key, "cbc", iv).decrypt(ct)
    open(out_path, "wb").write(dec)
    return True, f"{len(dec)}B (body byte-exact; first block needs a known header{'' if hdr else ' — none for '+ext})"


def main():
    ap = argparse.ArgumentParser(description="Everbe recovery (AES-256-CBC, captured key)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("recover-key"); a.add_argument("--in", dest="indir", required=True); a.add_argument("--trace", required=True)
    b = sub.add_parser("decrypt"); b.add_argument("--in", dest="indir", required=True)
    b.add_argument("--trace"); b.add_argument("--key"); b.add_argument("--out", required=True)
    b.add_argument("--known-size", dest="known", help="[validation] dir of original files -> full IV + exact trim (byte-exact)")
    args = ap.parse_args()

    if args.cmd == "recover-key":
        k = find_key(args.indir, args.trace)
        print(f"[+] AES-256 key: {k.hex()}" if k else "[-] key not found in trace")
        return

    key = bytes.fromhex(args.key) if args.key else find_key(args.indir, args.trace)
    if not key:
        sys.exit("[-] could not recover the AES key (give --trace <proc_dir> or --key <hex>)")
    print(f"[+] AES-256 key: {key.hex()}")
    os.makedirs(args.out, exist_ok=True)
    files = sorted(glob.glob(os.path.join(args.indir, "*" + EXT)))
    ok = exact = 0
    for f in files:
        _, base = _orig_ext(os.path.basename(f))
        try:
            good, info = decrypt_file(f, key, os.path.join(args.out, base), args.known)
            print(f"  [OK] {base}: {info}"); ok += 1; exact += int(good and "byte-exact=True" in info)
        except Exception as e:
            print(f"  [!!] {base}: {e}")
    print(f"\n[+] {ok}/{len(files)} written -> {args.out}" + (f"  ({exact} byte-exact vs originals)" if args.known else ""))


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    main()
