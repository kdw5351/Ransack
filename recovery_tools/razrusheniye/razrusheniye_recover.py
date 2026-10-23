#!/usr/bin/env python3
"""razrusheniye_recover — key-free recovery of Razrusheniye victim files.

Razrusheniye encrypts files with AES-256-CBC where the per-session key is produced by the CryptoAPI
chain CryptCreateHash -> CryptHashData -> CryptDeriveKey -> CryptEncrypt. A CryptDeriveKey key
lives only inside the CSP key object; it is never materialised in a process buffer, so the key
cannot be snapshotted (confirmed empirically: a known-plaintext search over every captured
buffer as key/IV found no match). The on-disk ciphertext therefore cannot be decrypted from
captured key material.

However, the file PLAINTEXT is passed to the encrypt sink (CryptEncrypt) immediately before the
buffer is overwritten in place. The instrumentation captures that plaintext residue
(`plain_<seq>.bin`, written by the plaintext-residue capture path of the PIN tool). This tool
reconstructs the original victim files directly from that residue — no key required.

This is a distinct recovery class from a decryptor:
  - decryptor (hdlocker): recover the KEY, then decrypt the ciphertext.
  - this tool (razrusheniye): recover the PLAINTEXT directly from the encrypt-time residue.

Subcommands:
  extract  <proc_dir> [out_dir]          reconstruct victim files from plain_*.bin (key-free)
  keysearch <proc_dir> <encrypted_file>  (diagnostic) brute captured buffers as AES key/IV

Required input: a trace directory containing the `plain_*.bin` residue snapshots.
No internet, no payment; Python 3.10+ (+ pycryptodome only for the optional keysearch diagnostic).
"""
import sys, os, glob, hashlib, struct

# file-type signatures used to identify and bound recovered content
MAGIC = [(b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip"), (b"7z\xbc\xaf\x27\x1c", "7z"),
         (b"Rar!\x1a\x07", "rar"), (b"\x1f\x8b", "gz"), (b"%PDF", "pdf"),
         (b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpg"), (b"GIF8", "gif"),
         (b"BM", "bmp"), (b"\xd0\xcf\x11\xe0", "doc"), (b"<?xml", "xml"), (b"ID3", "mp3"),
         (b"RIFF", "wav")]

def detect(b):
    for sig, name in MAGIC:
        if b.startswith(sig): return name
    if b[257:262] == b"ustar": return "tar"
    printable = sum(1 for x in b[:64] if 9 <= x <= 13 or 32 <= x < 127)
    return "txt" if printable >= 58 else None

def trim(b, kind):
    """The plaintext window over-reads small files into adjacent heap; cut at the logical end.
    Container formats trim exactly (CRC-perfect); text/markup cut at the first NUL (byte-exact)."""
    if kind == "zip":
        i = b.rfind(b"PK\x05\x06")
        if i >= 0 and i + 22 <= len(b):
            comment = struct.unpack("<H", b[i+20:i+22])[0]
            return b[:i + 22 + comment]
    elif kind == "png":
        i = b.find(b"IEND\xaeB`\x82")
        if i >= 0: return b[:i + 8]
    elif kind == "jpg":
        i = b.rfind(b"\xff\xd9")
        if i >= 0: return b[:i + 2]
    elif kind == "gif":
        i = b.rfind(b"\x00\x3b")
        if i >= 0: return b[:i + 2]
    elif kind == "pdf":
        i = b.rfind(b"%%EOF")
        if i >= 0:
            end = i + 5
            if b[end:end+2] == b"\r\n": end += 2
            elif b[end:end+1] in (b"\r", b"\n"): end += 1
            return b[:end]
    elif kind in ("xml", "txt"):
        # Text/markup has no NUL byte, so the FIRST 0x00 in the over-read buffer is exactly the
        # end of the file content -> byte-exact, no original/length hint needed.
        i = b.find(b"\x00")
        if i > 0:
            b = b[:i]
    return b

def extract(proc, out):
    os.makedirs(out, exist_ok=True)
    bins = sorted(glob.glob(os.path.join(proc, "plain_*.bin")) +
                  glob.glob(os.path.join(proc, "crypto_*.bin")),
                  key=lambda p: (os.path.basename(p).split("_")[0],
                                 int(os.path.basename(p).split("_")[1].split(".")[0])))
    seen, n = set(), 0
    for fn in bins:
        b = open(fn, "rb").read()
        if len(b) < 8: continue
        kind = detect(b)
        if not kind: continue
        h = hashlib.sha1(b[:4096]).hexdigest()
        if h in seen: continue
        seen.add(h)
        data = trim(b, kind)
        n += 1
        path = os.path.join(out, f"recovered_{n:03d}.{kind}")
        open(path, "wb").write(data)
        print(f"  {os.path.basename(fn):16s} -> {os.path.basename(path)}  ({kind}, {len(data)} B)")
    print(f"\nrecovered {n} files -> {out}")
    if n == 0:
        print("  no plaintext residue found. Collect with a build that writes plain_*.bin "
              "(plaintext-residue capture). Without it, Razrusheniye files are not recoverable "
              "(the AES key is CryptDeriveKey-derived and never buffered).")

def keysearch(proc, encfile):
    try:
        from Crypto.Cipher import AES
    except Exception:
        sys.exit("keysearch needs pycryptodome (pip install pycryptodome)")
    enc = open(encfile, "rb").read()
    keys, ivs = set(), {bytes(16)}
    for fn in glob.glob(os.path.join(proc, "*.bin")):
        bb = open(fn, "rb").read(96)
        if bb[:2] == b"\x08\x02":
            ln = int.from_bytes(bb[8:12], "little")
            if ln in (16, 32): keys.add(bb[12:12+ln])
        for off in range(0, 49, 4):
            if len(bb) >= off+32: keys.add(bb[off:off+32])
            if len(bb) >= off+16: keys.add(bb[off:off+16]); ivs.add(bb[off:off+16])
    keys = {k for k in keys if len(k) in (16, 32)}
    print(f"candidate keys={len(keys)} ivs={len(ivs)}")
    plains = [open(p, "rb").read() for p in glob.glob(os.path.join(proc, "plain_*.bin"))]
    for key in keys:
        for layout, ct, ivset in (("whole", enc, list(ivs)), ("ivhdr", enc[16:], [enc[:16]])):
            if len(ct) % 16: continue
            for iv in ivset:
                try: dec = AES.new(key, AES.MODE_CBC, iv).decrypt(ct[:64])
                except Exception: continue
                if detect(dec):
                    print(f"  DECRYPT HIT key={key.hex()} iv={iv.hex()} layout={layout}")
                    return
                for P in plains:
                    if len(P) >= 16:
                        try:
                            if AES.new(key, AES.MODE_CBC, iv).encrypt(P[:16]) == ct[:16]:
                                print(f"  KEY (known-plaintext) key={key.hex()} iv={iv.hex()}")
                                return
                        except Exception: pass
    print("  no key found — expected for Razrusheniye (CryptDeriveKey). Use 'extract' for key-free recovery.")

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__); sys.exit(0)
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    if sys.argv[1] == "extract":
        extract(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "recovered")
    elif sys.argv[1] == "keysearch" and len(sys.argv) >= 4:
        keysearch(sys.argv[2], sys.argv[3])
    else:
        print(__doc__); sys.exit(1)

if __name__ == "__main__":
    try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception: pass
    main()
