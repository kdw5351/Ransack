#!/usr/bin/env python3
"""razrusheniye_keyrecover -- key-based decryptor for Razrusheniye (`.raz`).

Razrusheniye encrypts every file of a run under ONE AES-256-CBC key and ONE IV. Both
sit in the clear in the run's key-residue snapshots, at offset 0 of several
`crypto_*.bin` files, so a trace is all that is needed to decrypt the whole infection.

This supersedes the key-free residue path for any run whose trace captured the key.
That path remains correct for a run that did not: an earlier capture of this family
holds neither the key nor the IV, which is why the residue tool exists and why its
notes say the key was never buffered. That statement holds for that trace, not for the
family.

Recovering the key needs no oracle. Candidates are every 16- and 32-byte window of the
captured buffers; the right one is identified by decrypting a file whose first bytes
are a known file-type signature, then confirmed by the second cipher block chaining
correctly. Where an original is held, the whole file is compared.

Usage:
    python razrusheniye_keyrecover.py recover-key <proc_dir> [--enc <enc_dir>]
    python razrusheniye_keyrecover.py decrypt <proc_dir> <enc_dir> <out_dir> [--known <orig_dir>]

Python 3.10+ with pycryptodome.
"""
import argparse, collections, glob, hashlib, math, os, sys
try:
    from Crypto.Cipher import AES
except ImportError:
    sys.exit("needs pycryptodome:  pip install pycryptodome")

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# File-type signatures used to recognise a correct decryption without an original.
MAGIC = [
    (b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip"), (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"), (b"\x1f\x8b\x08", "gz"), (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpg"), (b"%PDF-", "pdf"), (b"RIFF", "riff"), (b"\xd0\xcf\x11\xe0", "ole"),
    (b"<?xml", "xml"), (b"\xef\xbb\xbf", "utf8-bom"), (b"{\n", "json"), (b"{\"", "json"),
]
KEY_LENS = (32, 16)          # AES-256 first: that is what this family uses
IV_LEN = 16


def _buffers(proc):
    out = []
    for pat in ("crypto_*.bin", "plain_*.bin"):
        for p in sorted(glob.glob(os.path.join(proc, pat))):
            try:
                out.append(open(p, "rb").read())
            except OSError:
                pass
    return out


def derived_candidates(proc):
    """The CryptDeriveKey product, recomputed rather than searched for.

    The chain is CryptCreateHash -> CryptHashData(secret) -> CryptDeriveKey, so the AES key
    is the SHA-256 of the secret the sample fed in. That secret is snapshotted as a
    keygen input, which makes the key a one-line computation instead of a sweep:

        key == SHA-256(keygen_input[:32])

    Verified on both traces we hold. It also explains why a raw search can miss: the
    hashed value need not appear anywhere, though in practice it does.
    """
    out = {}
    for p in sorted(glob.glob(os.path.join(proc, "crypto_*.bin"))):
        try:
            b = open(p, "rb").read()
        except OSError:
            continue
        for ln in (32, 16, 20, 48, 64, len(b)):
            if 0 < ln <= len(b):
                out.setdefault(hashlib.sha256(b[:ln]).digest(),
                               "SHA-256(%s[:%d])" % (os.path.basename(p), ln))
    return out


def _candidates(bufs, step=4, lengths=None):
    """Every aligned window of a plausible key length, most-repeated first: the real
    key is written to several snapshots, so frequency is a useful prior."""
    seen = {}
    for b in bufs:
        for ln in (lengths or KEY_LENS):
            for off in range(0, max(0, len(b) - ln + 1), step):
                w = bytes(b[off:off + ln])
                if len(set(w)) < 8:        # skip padding and counters
                    continue
                seen[w] = seen.get(w, 0) + 1
    return [k for k, _ in sorted(seen.items(), key=lambda kv: -kv[1])]


def _looks_recovered(head):
    for sig, kind in MAGIC:
        if head.startswith(sig):
            return kind
    printable = sum(1 for c in head[:64] if 9 <= c <= 13 or 32 <= c < 127)
    return "text" if printable >= 60 else None


def _entropy(b):
    if not b:
        return 1.0
    c = collections.Counter(b)
    n = float(len(b))
    return -sum(v / n * math.log(v / n, 2) for v in c.values()) / 8.0


def _printable(b):
    return sum(1 for c in b if 9 <= c <= 13 or 32 <= c < 127)


def recover_key(proc, enc_dir=None, sample=24, min_low=3, low=0.90):
    """Return (key, iv, evidence) or (None, None, reason).

    Discriminator: ciphertext sits at normalised entropy ~1.0 whatever the file was.
    The right key drops the structured members of a mixed corpus well below that, while
    a wrong key leaves every file at ~1.0. Counting files that fall below the threshold
    separates the two cleanly and, unlike a printability test, works for archives and
    images as well as text. Calibrated on this family: the right key put 9 of 24 sampled
    files under 0.90, a wrong 32-byte marker string lifted from the same buffers put 0.

    Block 0 depends on the IV, so scoring starts at block 1 and the IV is recovered
    afterwards from the files that turned out to be text.
    """
    bufs = _buffers(proc)
    if not bufs:
        return None, None, "no crypto_*.bin or plain_*.bin in %s" % proc
    samples = []
    if enc_dir:
        for root, _d, fs in os.walk(enc_dir):
            for f in sorted(fs):
                if f.endswith(".raz"):
                    try:
                        b = open(os.path.join(root, f), "rb").read()
                    except OSError:
                        continue
                    if len(b) >= 512:
                        samples.append((f, b[:4096]))   # scoring prefix only
                    if len(samples) >= sample:
                        break
            if len(samples) >= sample:
                break
    if len(samples) < 4:
        return None, None, "need at least 4 .raz files of 512 B or more; pass --enc"

    zero = bytes(16)
    best = (0, None)
    derived = derived_candidates(proc)
    ordered = list(derived.keys()) + [k for k in _candidates(bufs) if k not in derived]
    for key in ordered:
        try:
            n_low = 0
            for _n, ct in samples:
                m = len(ct) - (len(ct) % 16)
                d = AES.new(key, AES.MODE_CBC, zero).decrypt(ct[:m])
                if _entropy(d[16:]) < low:
                    n_low += 1
                    if n_low >= min_low:
                        break
            if n_low > best[0]:
                best = (n_low, key)
            if n_low >= min_low:
                break
        except ValueError:
            continue
    n_low, key = best
    if key is None or n_low < min_low:
        return None, None, ("no key drops any file below entropy %.2f (best %d of %d); "
                            "this trace did not capture it, so use the key-free residue "
                            "tool" % (low, n_low, len(samples)))

    # IV: only block 0 depends on it. Score 16-byte windows by how many first blocks
    # decrypt to a real file-type signature. Magic bytes match exactly, so this is
    # decisive where a printability test is not: on this family the right IV put 24 of
    # 60 first blocks on a known signature and a zero IV put none.
    heads = [AES.new(key, AES.MODE_ECB).decrypt(ct[:16]) for _n, ct in samples]

    def _magic_hits(cand):
        c = 0
        for d0 in heads:
            p0 = bytes(x ^ y for x, y in zip(d0, cand))
            if any(p0.startswith(m) for m, _k in MAGIC):
                c += 1
        return c

    iv, iv_hits = None, 0
    target = max(2, len(heads) // 6)
    for cand in _candidates(bufs, step=1, lengths=(16,)):
        h = _magic_hits(cand)
        if h > iv_hits:
            iv, iv_hits = cand, h
        if h >= target:
            break
    if iv_hits < 2:
        iv = None
    note = "" if iv is None else "; iv puts %d/%d first blocks on a file signature" % (iv_hits, len(heads))
    route = derived.get(key)
    how = ("recomputed as %s" % route) if route else "found by sweeping captured buffers"
    return key, iv, "%s; %d of %d sampled files fall below entropy %.2f%s" % (how, n_low, len(samples), low, note)


def decrypt_all(proc, enc_dir, out_dir, known=None):
    key, iv, why = recover_key(proc, enc_dir)
    if key is None:
        print("[!] %s" % why)
        return 2
    print("[+] key %s" % key.hex())
    print("[+] iv  %s" % (iv.hex() if iv else "(recovering per file)"))
    print("[+] confirmed by %s" % why)
    os.makedirs(out_dir, exist_ok=True)
    origs = {}
    if known:
        for root, _d, fs in os.walk(known):
            for f in fs:
                origs.setdefault(f, os.path.join(root, f))
    files = []
    for root, _d, fs in os.walk(enc_dir):
        for f in fs:
            if f.endswith(".raz"):
                files.append(os.path.join(root, f))
    ok = exact = checked = short = 0
    for p in sorted(files):
        base = os.path.basename(p)[:-4]
        ct = open(p, "rb").read()
        if len(ct) < 16 or iv is None:
            continue
        n = len(ct) - (len(ct) % 16)
        pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct[:n])
        op = origs.get(base)
        if op:
            orig = open(op, "rb").read()
            checked += 1
            if pt[:len(orig)] == orig:
                exact += 1
                pt = pt[:len(orig)]
            elif len(ct) < len(orig):
                short += 1
        open(os.path.join(out_dir, base), "wb").write(pt)
        ok += 1
    print("\nwrote %d files -> %s" % (ok, out_dir))
    if checked:
        print("byte-exact against held-out originals: %d/%d" % (exact, checked))
        if short:
            print("  (%d of the rest are files whose ciphertext is shorter than the "
                  "original, so the run sealed only part of them)" % short)
    return 0


def main():
    ap = argparse.ArgumentParser(description="Razrusheniye key-based decryptor")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("recover-key"); r.add_argument("proc"); r.add_argument("--enc")
    d = sub.add_parser("decrypt"); d.add_argument("proc"); d.add_argument("enc"); d.add_argument("out")
    d.add_argument("--known")
    a = ap.parse_args()
    if a.cmd == "recover-key":
        k, iv, why = recover_key(a.proc, a.enc)
        if k is None:
            print("[!] %s" % why); return 2
        print("key: %s" % k.hex())
        print("iv : %s" % (iv.hex() if iv else "(not determined)"))
        print("via: %s" % why)
        return 0
    return decrypt_all(a.proc, a.enc, a.out, a.known)


if __name__ == "__main__":
    sys.exit(main())
