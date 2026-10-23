#!/usr/bin/env python3
"""
Chaos ransomware recovery (AES-256-CBC; per-file key+IV captured at the RSA-wrap boundary).

Scheme (reverse-engineered + verified byte-exact):
  - **AES-256-CBC, raw ASCII key + IV.** Each file gets a fresh **32-char key + 16-char IV**, used
    DIRECTLY as the AES-256 key (the 32 ASCII bytes) and the IV (the 16 ASCII bytes) — no KDF. The
    sample formats them as `"KEY|IV"` (49 bytes) and **RSA-2048-wraps** that blob for the operator.
  - **The Ransack trace captures the plaintext `"KEY|IV"`** the instant it is handed to `BCryptEncrypt`
    (the RSA-wrap input, a `sink_plaintext` snapshot) — i.e. *before* it is sealed. So each file's key
    is captured in `crypto_*.bin`. The keys come from a strong RNG (`CryptGenRandom`) and are otherwise
    RSA-protected, so they cannot be brute-forced or derived post-hoc — recovery depends on the capture.
  - **Encrypted-file layout:** `[AES ciphertext] + [256-byte RSA-wrapped key trailer]`.
      * **Small files** (<= ~384 KB): the WHOLE file is AES-256-CBC + PKCS#7 (`body = padded plaintext`).
      * **Large files:** **intermittent** — three 128 KB chunks (head / middle / tail) are AES-CBC
        encrypted, the gaps between them are left as plaintext. Each chunk uses its own captured key|iv.

Recovery class: **captured symmetric key material** (cf. PayBreak; RC-07). NOT a universal decryptor and
NOT a break of AES/RSA — it recovers an infection only from the trace of *that* run.

Usage:
  python chaos_recover.py list-keys --trace <proc_dir>
  python chaos_recover.py decrypt --in <enc_dir> --trace <proc_dir> --out <dir> [--known-size <orig_dir>]
"""
import os, sys, glob, re, argparse
from collections import OrderedDict

PARTIAL     = 131072   # 128 KB AES chunk size used by the intermittent (large-file) mode
RSA_TRAILER = 256      # RSA-2048-wrapped "KEY|IV" appended to every encrypted file
FULL_MAX    = PARTIAL * 3   # at/under this size the whole file is encrypted (the 3 chunks would cover it)
KEYIV = re.compile(rb'([A-Za-z0-9]{32})\|([A-Za-z0-9]{16})')
MAGICS = [b"\x89PNG", b"\xff\xd8\xff", b"%PDF", b"PK\x03\x04", b"7z\xbc\xaf", b"\x1f\x8b\x08",
          b"Rar!", b"GIF8", b"BM", b"ID3", b"<?xml", b"MZ", b"{", b"["]


def _ecb(key):
    from Crypto.Cipher import AES
    return AES.new(key, AES.MODE_ECB)


def _cbc(key, iv):
    from Crypto.Cipher import AES
    return AES.new(key, AES.MODE_CBC, iv)


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _unpad(d):
    if d and 1 <= d[-1] <= 16 and d[-d[-1]:] == bytes([d[-1]]) * d[-1]:
        return d[:-d[-1]]
    return d


def _printable(b):
    return sum(1 for c in b if 9 <= c <= 13 or 32 <= c < 127) / max(1, len(b))


def harvest_keys(proc_dir):
    """Distinct (key, iv) captured in the trace's crypto_*.bin (the plaintext "KEY|IV" RSA-wrap inputs)."""
    seen = OrderedDict()
    for fn in glob.glob(os.path.join(proc_dir, "crypto_*.bin")):
        try:
            b = open(fn, "rb").read()
        except OSError:
            continue
        for m in KEYIV.finditer(b):
            seen[(m.group(1), m.group(2))] = None
    return list(seen.keys())


def _coherent(p0):
    """A correctly-decrypted first block is a known magic or mostly-printable; random (wrong key) is not."""
    return any(p0.startswith(m) for m in MAGICS) or _printable(p0) > 0.85


def find_key(c0, keys, target=None):
    """Find the (key, iv) whose CBC first-block decryption of c0 equals `target` (when known) or is coherent."""
    for (k, iv) in keys:
        p0 = _xor(_ecb(k).decrypt(c0), iv)
        if (target is not None and p0 == target) or (target is None and _coherent(p0)):
            return (k, iv)
    return None


def decrypt_file(ct, keys, orig=None):
    """Decrypt one Chaos file. Returns (plaintext_or_None, info). `orig` (if given) enables exact key
    selection + byte-exact reporting."""
    if len(ct) < 16 + RSA_TRAILER:
        return None, "too-short / not-encrypted"
    body = ct[:len(ct) - RSA_TRAILER]

    # --- full mode: whole body is AES-256-CBC + PKCS#7 (small files) ---
    if len(body) % 16 == 0 and len(body) <= FULL_MAX + 16:
        key = find_key(body[:16], keys, orig[:16] if orig else None)
        if key:
            pt = _unpad(_cbc(key[0], key[1]).decrypt(body))
            if orig is None or pt == orig:
                return pt, f"full {len(pt)}B" + (" byte-exact" if orig is not None else "")

    # --- intermittent mode: head / middle / tail 128 KB AES chunks, plaintext gaps (large files) ---
    out = bytearray(body)
    half = (len(body) // 2) // 16 * 16
    end = (len(body) // 16) * 16
    chunks = [(0, PARTIAL), (half, half + PARTIAL), (max(0, end - PARTIAL), end)]
    # For bodies in (FULL_MAX, ~512 KB) the middle and tail 128 KB windows overlap.
    # Clip each window's end to the next window's start so the overlap is decrypted
    # exactly once and owned by the later (tail-priority) window, matching the
    # last-writer-wins order of the malware's own overlapping encryption. This is
    # output-identical to the previous decrypt-twice code (tail already overwrote
    # the band) but avoids the wasted, confusing double CBC pass.
    overlap = False
    for i in range(len(chunks) - 1):
        a, b = chunks[i]
        nxt = chunks[i + 1][0]
        if b > nxt:
            chunks[i] = (a, nxt)
            overlap = True
    missing = []
    found_any = False
    for (a, b) in chunks:
        a = max(0, a)
        b = min(len(body), b)
        al = (b - a) // 16 * 16
        if al <= 0:
            continue
        key = find_key(body[a:a + 16], keys, orig[a:a + 16] if orig else None)
        if not key:
            missing.append(a)
            continue
        out[a:a + al] = _cbc(key[0], key[1]).decrypt(body[a:a + al])
        found_any = True
    if not found_any:
        return None, "no-key (key|iv not captured in this trace)"
    info = f"intermittent {len(out)}B"
    if missing:
        info += f" — {len(missing)} chunk(s) key-not-captured (left as ciphertext)"
    if overlap and orig is None:
        info += " — NOTE: overlapping middle/tail windows (~384-512 KB file); the "\
                "overlap band is decrypted with the tail window's chain, unverifiable "\
                "without the original"
    if orig is not None:
        info += " byte-exact" if bytes(out) == orig else " PARTIAL"
    return bytes(out), info


def cmd_decrypt(args):
    keys = harvest_keys(args.trace) if args.trace else []
    if not keys:
        sys.exit("[-] no key|iv captured in --trace (give the proc_dir from the same run)")
    print(f"[+] {len(keys)} captured key|iv loaded from trace")
    os.makedirs(args.out, exist_ok=True)
    files = [f for f in sorted(glob.glob(os.path.join(args.indir, "*"))) if os.path.isfile(f)]
    ok = exact = nokey = skipped = 0
    for f in files:
        name = os.path.basename(f)
        base = name.rsplit(".", 1)[0] if "." in name else name      # strip the random extension
        ct = open(f, "rb").read()
        orig = None
        if args.known:
            op = os.path.join(args.known, base)
            if os.path.isfile(op):
                orig = open(op, "rb").read()
                if ct == orig:                                      # Chaos left this one unencrypted
                    print(f"  [--] {base}: not encrypted (intact)")
                    skipped += 1
                    continue
        pt, info = decrypt_file(ct, keys, orig)
        if pt is None:
            print(f"  [!!] {base}: {info}")
            nokey += 1
            continue
        open(os.path.join(args.out, base), "wb").write(pt)
        ok += 1
        exact += int("byte-exact" in info)
        print(f"  [OK] {base}: {info}")
    tail = f"  ({exact} byte-exact vs originals)" if args.known else ""
    print(f"\n[+] {ok}/{len(files)} written -> {args.out}{tail}"
          + (f"  | {nokey} no-key, {skipped} unencrypted" if (nokey or skipped) else ""))


def cmd_listkeys(args):
    keys = harvest_keys(args.trace)
    print(f"[+] {len(keys)} distinct captured key|iv:")
    for k, iv in keys[:20]:
        print(f"    key={k.decode()}  iv={iv.decode()}")
    if len(keys) > 20:
        print(f"    ... (+{len(keys) - 20} more)")


def main():
    ap = argparse.ArgumentParser(description="Chaos recovery (AES-256-CBC, per-file captured key|iv)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("list-keys")
    a.add_argument("--trace", required=True)
    b = sub.add_parser("decrypt")
    b.add_argument("--in", dest="indir", required=True)
    b.add_argument("--trace", required=True)
    b.add_argument("--out", required=True)
    b.add_argument("--known-size", dest="known", help="[validation] dir of original files -> byte-exact check")
    args = ap.parse_args()
    (cmd_listkeys if args.cmd == "list-keys" else cmd_decrypt)(args)


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    main()
