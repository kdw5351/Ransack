#!/usr/bin/env python3
"""
Akira ransomware PARTIAL recovery -- key-free salvage of the un-encrypted regions.

Akira uses **intermittent (partial) encryption**: it ChaCha8-encrypts only part of each
file and leaves the rest as plaintext. The ChaCha key is wrapped with the operators'
RSA-4096 public key and appended in a footer -- so the *encrypted* part is unrecoverable
without the operators' private key. BUT the **plaintext part needs no key at all** -- it can
be salvaged directly from the encrypted file.

Encryption layout (reverse-engineered, then verified byte-exact against originals):
  - footer: a 534-byte trailer is appended to finalized `<name>.akira` files (RSA-wrapped key + meta).
  - file body <= 2,000,000 bytes : the **first half** `[0 : size//2]` is encrypted; the
    **second half `[size//2 : size]` is plaintext** -> fully salvageable, no key.
  - file body  > 2,000,000 bytes : only a few blocks are encrypted (Akira docs: 4 blocks); the
    large majority is plaintext. The captured sample (interrupted) shows a leading encrypted
    block; the rest is plaintext (98% of a 19 MB file salvaged byte-exact).

This is a *partial* recovery: the encrypted region stays lost (RSA-4096 wall). It is most
useful for linear/append formats (logs, CSV, SQL dumps, text, DB) where the salvaged tail is
directly usable, and for large files (>2 MB) where almost everything is plaintext.

Usage:
  # salvage (no key, no trace needed) -- writes recovered files with encrypted bytes zero-filled:
  python akira_salvage.py recover --in <enc_dir> --out <out_dir>
  #   add --prefix-enc 393216  to force a known leading encrypted-block size for >2MB files
  # verify against held originals (reports byte-exact on the salvaged regions + recovery %):
  python akira_salvage.py recover --in <enc_dir> --out <out_dir> --orig <orig_dir>
"""
import os, sys, glob, math, argparse

EXT = ".akira"
FOOTER = 534
THRESH = 2_000_000

def _entropy(b):
    if not b:
        return 0.0
    from collections import Counter
    n = len(b); c = Counter(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())

def enc_regions(body, prefix_enc=None):
    """Byte ranges that are ChaCha-encrypted (to skip / zero-fill)."""
    n = len(body)
    if n <= THRESH:
        return [(0, n // 2)]                       # first half encrypted (verified)
    if prefix_enc:
        return [(0, min(prefix_enc, n))]           # known leading block (captured-sample layout)
    # best-effort for >2MB without a known layout: mark high-entropy windows as encrypted.
    # reliable for low-entropy originals (text/log/db); compressed originals are ~indistinguishable.
    W = 65536; regs = []; cur = None
    for w in range(0, n, W):
        enc = _entropy(body[w:w + W]) > 7.9
        if enc and cur is None: cur = w
        elif not enc and cur is not None: regs.append((cur, w)); cur = None
    if cur is not None: regs.append((cur, n))
    return regs

def salvage_body(enc_bytes, has_footer, prefix_enc=None):
    body = enc_bytes[:-FOOTER] if (has_footer and len(enc_bytes) > FOOTER) else enc_bytes
    regs = enc_regions(body, prefix_enc)
    out = bytearray(body)
    enc_total = 0
    for s, e in regs:
        out[s:e] = b"\x00" * (e - s); enc_total += (e - s)
    return bytes(out), regs, len(body) - enc_total

def cmd_recover(args):
    files = sorted(glob.glob(os.path.join(args.indir, "*" + EXT)))
    # also include partially-processed files (no .akira suffix) if present? keep to .akira for safety
    if not files:
        sys.exit(f"[-] no *{EXT} files in {args.indir}")
    os.makedirs(args.out, exist_ok=True)
    tot_rec = tot_body = 0; exact = checked = 0
    for f in files:
        name = os.path.basename(f)[:-len(EXT)]
        enc = open(f, "rb").read()
        out, regs, rec = salvage_body(enc, has_footer=True, prefix_enc=args.prefix_enc)
        open(os.path.join(args.out, name), "wb").write(out)
        line = f"  [salvage] {name}: {rec}/{len(out)} B plaintext ({100*rec/max(1,len(out)):.1f}%)"
        if args.orig:
            o = os.path.join(args.orig, name)
            if os.path.isfile(o):
                orig = open(o, "rb").read()
                plain_ok = _plain_exact(out, orig, regs)
                checked += 1; exact += plain_ok
                line += f"  | vs original: {'BYTE-EXACT' if plain_ok else 'MISMATCH'}"
        print(line)
        tot_rec += rec; tot_body += len(out)
    print(f"\n[+] salvaged plaintext = {tot_rec}/{tot_body} bytes ({100*tot_rec/max(1,tot_body):.1f}%) -> {args.out}")
    if args.orig:
        print(f"[+] byte-exact on salvaged regions: {exact}/{checked} files")

def _plain_exact(out, orig, regs):
    n = min(len(out), len(orig))
    enc = [False] * n
    for s, e in regs:
        for i in range(s, min(e, n)): enc[i] = True
    return all(out[i] == orig[i] for i in range(n) if not enc[i])

def main():
    ap = argparse.ArgumentParser(description="Akira partial recovery (key-free salvage of plaintext regions)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("recover")
    r.add_argument("--in", dest="indir", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--orig", default=None, help="dir of originals -> verify byte-exact + recovery %")
    r.add_argument("--prefix-enc", type=int, default=None, help="known leading encrypted-block size for >2MB files")
    args = ap.parse_args()
    cmd_recover(args)

if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    main()
