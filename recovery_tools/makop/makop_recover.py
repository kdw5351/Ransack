#!/usr/bin/env python3
"""makop_recover — key-free recovery of Makop (Phobos-family) victim files.

Makop encrypts each file under a per-file random AES key and seals that key in a small per-file
footer using the operator's RSA public key (the trace shows an RSA1 public-key blob import; no
private key ever appears). The on-disk `.mkp` therefore cannot be decrypted from anything the
victim has: the only symmetric key materialised in a process buffer is Makop's *config*-decryption
key (a static PLAINTEXTKEYBLOB AES-256 key), and that key does NOT decrypt file data — confirmed
by an exhaustive trial over every captured key against every `.mkp` in all standard modes.

This tool was therefore developed from a *different* piece of information the Ransack analysis tool
captures: the **plaintext residue** at the encrypt sink. Makop hands each file's plaintext to
`CryptEncrypt` in a buffer that is overwritten in place; the instrumentation snapshots that buffer
*before* the cipher runs (`plain_<seq>.bin`). That residue is the original file content, so victim
files are reconstructed with **no key at all**.

Recovery class (third in the project, shared with Razrusheniye):
  - decryptor      (hdlocker)            : recover the KEY, then decrypt.
  - plaintext residue (razrusheniye / makop) : recover the PLAINTEXT directly from the encrypt-time
                                               residue — works even when the file key is RSA-sealed.

Subcommands:
  extract  <proc_dir> [out_dir]         reconstruct victim files from plain_*.bin (key-free)
  keyprobe <proc_dir> [enc.mkp]         (diagnostic) show the captured AES key is a config key and
                                        does NOT decrypt .mkp file data (why a decryptor is impossible)

Required input: a trace directory containing the `plain_*.bin` residue snapshots.
No internet, no payment; Python 3.10+ (pycryptodome only for the optional keyprobe diagnostic).
"""
import sys, os, glob, hashlib, struct

# file-type signatures used to identify and bound recovered residue
MAGIC = [(b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip"), (b"7z\xbc\xaf\x27\x1c", "7z"),
         (b"Rar!\x1a\x07", "rar"), (b"\x1f\x8b", "gz"), (b"%PDF", "pdf"),
         (b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpg"), (b"GIF8", "gif"),
         (b"BM", "bmp"), (b"\xd0\xcf\x11\xe0", "doc"), (b"<?xml", "xml"), (b"ID3", "mp3"),
         (b"RIFF", "wav")]


def detect(b):
    for sig, name in MAGIC:
        if b.startswith(sig):
            return name
    if b[257:262] == b"ustar":
        return "tar"
    printable = sum(1 for x in b[:64] if 9 <= x <= 13 or 32 <= x < 127)
    return "txt" if printable >= 58 else None


def trim(b, kind):
    """The plaintext window over-reads small files into adjacent heap; cut at the logical end.
    Container formats trim exactly (CRC-perfect); text/markup is trimmed at the first 0x00 byte
    (byte-exact because the text contains no NUL)."""
    if kind == "zip":
        i = b.rfind(b"PK\x05\x06")
        if i >= 0 and i + 22 <= len(b):
            comment = struct.unpack("<H", b[i+20:i+22])[0]
            return b[:i + 22 + comment]
    elif kind == "png":
        i = b.find(b"IEND\xaeB`\x82")
        if i >= 0:
            return b[:i + 8]
    elif kind == "jpg":
        i = b.rfind(b"\xff\xd9")
        if i >= 0:
            return b[:i + 2]
    elif kind == "gif":
        i = b.rfind(b"\x00\x3b")
        if i >= 0:
            return b[:i + 2]
    elif kind == "pdf":
        i = b.rfind(b"%%EOF")
        if i >= 0:
            end = i + 5
            if b[end:end+2] == b"\r\n":
                end += 2
            elif b[end:end+1] in (b"\r", b"\n"):
                end += 1
            return b[:end]
    elif kind in ("xml", "txt"):
        # Text/markup contains no NUL bytes, so the FIRST 0x00 in the over-read buffer is
        # exactly where the file content ends. Cutting there is byte-exact and needs NO
        # original/length hint (the boundary comes from the data itself, not a reference file).
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
        if len(b) < 8:
            continue
        kind = detect(b)
        if not kind:
            continue
        h = hashlib.sha1(b[:4096]).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        data = trim(b, kind)
        n += 1
        path = os.path.join(out, f"recovered_{n:03d}.{kind}")
        open(path, "wb").write(data)
        print(f"  {os.path.basename(fn):16s} -> {os.path.basename(path)}  ({kind}, {len(data)} B)")
    print(f"\nrecovered {n} files -> {out}")
    if n == 0:
        print("  no plaintext residue found. Collect with a build that writes plain_*.bin "
              "(plaintext-residue capture) on a run that ENCRYPTS fresh files. A run over "
              "already-encrypted files captures no plaintext (it only decrypts config).")


def keyprobe(proc, encfile=None):
    """Diagnostic: extract the captured AES key and demonstrate it does NOT decrypt file data."""
    try:
        from Crypto.Cipher import AES
    except Exception:
        sys.exit("keyprobe needs pycryptodome (pip install pycryptodome)")
    # collect PLAINTEXTKEYBLOB AES keys captured in the trace (08 02 00 00 | CALG | len | key)
    keys = set()
    for fn in glob.glob(os.path.join(proc, "*.bin")):
        d = open(fn, "rb").read(96)
        i = d.find(b"\x08\x02\x00\x00")
        if i >= 0 and i + 12 <= len(d):
            calg = int.from_bytes(d[i+4:i+8], "little")
            klen = int.from_bytes(d[i+8:i+12], "little")
            if calg in (0x6610, 0x660e) and klen in (16, 32) and i + 12 + klen <= len(d):
                keys.add(d[i+12:i+12+klen])
    print(f"captured PLAINTEXTKEYBLOB AES keys: {len(keys)}")
    for k in keys:
        print(f"  {k.hex()}  (this is Makop's CONFIG-decryption key, not a file key)")
    if not encfile:
        cand = glob.glob(os.path.join(proc, "..", "*.mkp")) + glob.glob("*.mkp")
        encfile = cand[0] if cand else None
    if not encfile or not os.path.isfile(encfile):
        print("  (no .mkp given; skipping the decrypt trial)")
        return
    d = open(encfile, "rb").read()
    print(f"\ntrying every captured key on {os.path.basename(encfile)} "
          f"({len(d)} B, size%16={len(d)%16}) in CBC/ECB/CFB/OFB x IVs x footers ...")
    modes = {"CBC": AES.MODE_CBC, "ECB": AES.MODE_ECB, "CFB": AES.MODE_CFB, "OFB": AES.MODE_OFB}
    hit = False
    for key in keys:
        for foot in (0, 4, 212, 228):
            ct = d[:len(d) - foot]
            ct = ct[:len(ct) // 16 * 16]
            if len(ct) < 32:
                continue
            for mn, mode in modes.items():
                for iv in (bytes(16), d[:16]):
                    try:
                        c = AES.new(key, mode) if mode == AES.MODE_ECB else AES.new(key, mode, iv)
                        dec = c.decrypt(ct[:64])
                    except Exception:
                        continue
                    if detect(dec):
                        print(f"  UNEXPECTED DECRYPT key={key.hex()} mode={mn} foot={foot}")
                        hit = True
    if not hit:
        print("  NO key decrypts the file data -> per-file AES key is RSA-sealed in the footer "
              "(unrecoverable). Use 'extract' for key-free residue recovery.")


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    if sys.argv[1] == "extract":
        extract(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "recovered")
    elif sys.argv[1] == "keyprobe":
        keyprobe(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    main()
