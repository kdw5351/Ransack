"""
hdlocker_decrypt.py -- HDLocker universal recovery tool (self-contained, blind).

Recovers files encrypted by HDLocker (renamed *_HD). Offline: needs only the locked
files + the bundled keyspace. No note, no trace, no memory dump, no original required.

Pipeline:
  1. Brute-force the 16-byte TEA key by sliding a window over hdlocker_keyspace.bin
     (~73,713 candidates, ~3 s), keeping the candidate that decrypts to structured content.
  2. Decrypt every *_HD file (TEA-16, custom CBC, IV=0).
  3. Recover the per-file framing BLIND:
       - large files: deterministic layout (fixed 9-byte offset + 50,000-byte head + tail).
       - small files: [random 3-10 B prefix | content | 7-B pad]. The prefix boundary is
         located from CONTENT structure (Pass 1: file magic / null-run / periodicity /
         extension hint / ASCII edge), and any residual low-confidence file is resolved by
         Pass 2: cross-file alignment against already-recovered high-confidence content.

The prefix carries NO length field, so a single high-entropy file with no magic and no
peer sharing its content is the one irreducible ambiguity; the tool flags it rather than
guessing. `--known-size` remains only as an optional exact-length validation switch.
"""
import argparse
import os
import struct
import sys
import time

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass


def resource_path(relname):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relname)
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, relname)

# ---- TEA-BE-16round primitive ----
DELTA = 0x9E3779B9
MASK32 = 0xFFFFFFFF
MAGIC = b'HDLocker_'
CIPHER_REGION_SIZE = 50016
LARGE_FILE_THRESHOLD = 50016
TRAIL_PAD = 7


def tea_dec(in8, key, rounds=16):
    v0, v1 = struct.unpack('>II', in8); k = struct.unpack('>IIII', key)
    s = (DELTA * rounds) & MASK32
    for _ in range(rounds):
        v1 = (v1 - ((((v0 << 4) & MASK32) + k[2]) ^ (v0 + s) ^ ((v0 >> 5) + k[3]))) & MASK32
        v0 = (v0 - ((((v1 << 4) & MASK32) + k[0]) ^ (v1 + s) ^ ((v1 >> 5) + k[1]))) & MASK32
        s = (s - DELTA) & MASK32
    return struct.pack('>II', v0, v1)


def recover_pt(body, key, iv=b'\x00' * 8):
    pt = bytearray()
    nblocks = len(body) // 8
    if nblocks == 0:
        return bytes(pt)
    tea_in_prev = tea_dec(body[0:8], key)
    pt += bytes(tea_in_prev[j] ^ iv[j] for j in range(8))
    body_prev = body[0:8]
    for i in range(1, nblocks):
        c = body[i * 8:i * 8 + 8]
        tea_out_i = bytes(c[j] ^ tea_in_prev[j] for j in range(8))
        tea_in_i = tea_dec(tea_out_i, key)
        pt += bytes(tea_in_i[j] ^ body_prev[j] for j in range(8))
        tea_in_prev = tea_in_i
        body_prev = c
    return bytes(pt)


def _is_ascii(b):
    return (0x20 <= b < 0x7f) or b in (9, 10, 13)


def longest_ascii_run(data):
    best = cur = 0
    for b in data:
        if _is_ascii(b):
            cur += 1
            if cur > best: best = cur
        else:
            cur = 0
    return best


def score_candidate(pt):
    if len(pt) < 16:
        return 0
    best = 0
    for prefix_len in range(0, 9):
        chunk = pt[prefix_len:prefix_len + 16]
        if len(chunk) < 16:
            continue
        s = sum(1 for b in chunk if _is_ascii(b))
        if s > best:
            best = s
    return best


def find_tea_key(body, keyspace, top_n=5):
    coarse = []
    test_body = body[:24]
    for off in range(len(keyspace) - 16 + 1):
        key = keyspace[off:off + 16]
        try:
            pt = recover_pt(test_body, key)
        except Exception:
            continue
        s = score_candidate(pt)
        if s >= 12:
            coarse.append((s, off, key))
    coarse.sort(reverse=True)
    coarse = coarse[:max(top_n, 200)]
    refine_body = body[:min(1024, len(body))]
    refined = []
    for _s, off, key in coarse:
        try:
            pt = recover_pt(refine_body, key)
        except Exception:
            continue
        nuls = pt.count(0)
        ok = sum(1 for b in pt if _is_ascii(b))
        run = longest_ascii_run(pt)
        refined.append((run, ok - 2 * nuls, off, key))
    refined.sort(reverse=True)
    return [(run, off, key) for run, _ok, off, key in refined[:top_n]]


# ---------------------------------------------------------------------------
#  Blind per-file prefix detection (Pass 1)
# ---------------------------------------------------------------------------
# Real file-format magics, keyed by the extension preserved in the locked name.
REAL_MAGIC = {
    '.rar': b'Rar!\x1a\x07', '.7z': b'7z\xbc\xaf\x27\x1c', '.gz': b'\x1f\x8b',
    '.zip': b'PK\x03\x04', '.docx': b'PK\x03\x04', '.xlsx': b'PK\x03\x04',
    '.pptx': b'PK\x03\x04', '.png': b'\x89PNG\r\n\x1a\n', '.pdf': b'%PDF',
    '.jpg': b'\xff\xd8\xff', '.jpeg': b'\xff\xd8\xff', '.gif': b'GIF8',
    '.bmp': b'BM', '.doc': b'\xd0\xcf\x11\xe0', '.xls': b'\xd0\xcf\x11\xe0',
    '.ppt': b'\xd0\xcf\x11\xe0', '.exe': b'MZ', '.dll': b'MZ', '.elf': b'\x7fELF',
    '.bz2': b'BZh', '.xz': b'\xfd7zXZ', '.tar': None,  # tar magic 'ustar' at 257
}
EXT_FIRST = {
    '.xml': set(b'<'), '.html': set(b'<'), '.htm': set(b'<'), '.svg': set(b'<'),
    '.json': set(b'{['), '.yaml': set(b'-#'), '.yml': set(b'-#'),
    '.md': set(b'#*->'), '.csv': None, '.tsv': None, '.log': None,
    '.sql': None, '.ini': set(b'[;'), '.py': set(b'#\'"idfrc'),
    '.js': set(b'/({[\'"'), '.c': set(b'/#'), '.h': set(b'/#'),
}

DECISIVE = 5000   # score at/above this means a structural signal fired -> high confidence


def _ext_of(filename):
    ext = os.path.splitext(filename.lower())[1]
    if ext.endswith('_hd'):
        ext = os.path.splitext(filename.lower()[:-3])[1]
    return ext


def blind_prefix_single(pt, filename):
    """Return (prefix, score, margin). score>=DECISIVE => high confidence."""
    n = len(pt)
    ext = _ext_of(filename)
    magic = REAL_MAGIC.get(ext)
    ext_first = EXT_FIRST.get(ext)
    scored = []
    for off in range(3, 11):
        if off + TRAIL_PAD > n:
            continue
        content = pt[off:n - TRAIL_PAD]
        if not content:
            continue
        sc = 0
        # (1) real file magic at content start -- decisive
        if magic and content[:len(magic)] == magic:
            sc += 1_000_000
        # tar: 'ustar' at offset 257 of content
        if ext == '.tar' and len(content) > 262 and content[257:262] == b'ustar':
            sc += 1_000_000
        # (2) null-run onset: content begins with a long zero run, boundary byte nonzero
        z = 0
        for b in content[:64]:
            if b == 0: z += 1
            else: break
        if z >= 8:
            sc += 6000 + z
            if pt[off - 1] != 0:
                sc += 400
        # (3) periodicity onset: content is k-periodic (repetitive payloads / structured dumps)
        for period in (16, 8, 4, 12):
            if len(content) >= period * 3 and any(content[:period]) \
               and content[:period] == content[period:2 * period] == content[2 * period:3 * period]:
                sc += 8000 + (period == 16) * 200
                if pt[off - 1] != content[0]:
                    sc += 300
                break
        # (4) extension-guided first byte
        if ext_first and content[0] in ext_first:
            sc += 2000
        # (5) leading ASCII run + edge (prefix byte should look non-textual)
        run = 0
        for b in content[:256]:
            if _is_ascii(b): run += 1
            else: break
        sc += min(run, 220)
        if not _is_ascii(pt[off - 1]):
            sc += 25
        scored.append((sc, off))
    if not scored:
        return 7, 0, 0
    scored.sort(reverse=True)
    best_sc, best_off = scored[0]
    margin = best_sc - (scored[1][0] if len(scored) > 1 else 0)
    return best_off, best_sc, margin


def large_file_content(body, key):
    """Deterministic large-file layout: plain_tail | 16B sep | 50000B cipher; head=[9:50009]."""
    tail_len = len(body) - CIPHER_REGION_SIZE
    dec = recover_pt(body[tail_len:], key)
    return dec[9:9 + 50000] + body[:tail_len]


def cross_file_align(pt, anchors):
    """Resolve a low-confidence small file by aligning its content to any anchor
    (a high-confidence recovered content that shares this file's data). Returns
    (prefix, True) on a unique match, else (None, False)."""
    n = len(pt)
    hits = []
    for off in range(3, 11):
        if off + TRAIL_PAD > n:
            continue
        content = pt[off:n - TRAIL_PAD]
        if not content:
            continue
        for a in anchors:
            if len(content) <= len(a) and content == a[:len(content)]:
                hits.append(off); break
            if len(a) <= len(content) and a == content[:len(a)] and len(a) >= 32:
                hits.append(off); break
    uniq = sorted(set(hits))
    if len(uniq) == 1:
        return uniq[0], True
    return None, False


# ---------------------------------------------------------------------------
def prompt(question, default=None):
    extra = f" [{default}]" if default else ""
    try:
        s = input(f"  {question}{extra}: ").strip().strip('"').strip("'")
    except EOFError:
        s = ''
    return s if s else default


def main():
    ap = argparse.ArgumentParser(
        description='HDLocker Universal Decryptor -- blind recovery (no note, no original).')
    ap.add_argument('--in-dir', help='folder with *_HD locked files')
    ap.add_argument('--out-dir', help='output folder for recovered files')
    ap.add_argument('--keyspace', default=resource_path('hdlocker_keyspace.bin'))
    ap.add_argument('--known-size', help='[validation only] dir of originals; forces exact prefix from size')
    args = ap.parse_args()

    print("=" * 70); print("HDLocker Universal Recovery Tool (blind)"); print("=" * 70)
    if not args.in_dir:
        args.in_dir = prompt("Locked folder (--in-dir)")
    if not args.in_dir or not os.path.isdir(args.in_dir):
        print(f"[!] invalid folder: {args.in_dir}"); sys.exit(1)
    if not args.out_dir:
        args.out_dir = prompt("Output folder (--out-dir)",
                              os.path.join(os.path.dirname(args.in_dir.rstrip('\\/')) or '.', 'HDLocker_recovered'))

    if not os.path.exists(args.keyspace):
        print(f"[!] keyspace not found: {args.keyspace}"); sys.exit(1)
    keyspace = open(args.keyspace, 'rb').read()
    hd_files = sorted(f for f in os.listdir(args.in_dir) if f.endswith('_HD'))
    if not hd_files:
        print(f"[!] no *_HD files in {args.in_dir}"); sys.exit(1)
    print(f"[*] {len(hd_files)} locked files; keyspace {len(keyspace):,} B")

    # --- recover TEA key from the largest cipher region ---
    sized = []
    for f in hd_files:
        bs = os.path.getsize(os.path.join(args.in_dir, f)) - len(MAGIC)
        if bs < 16: continue
        cl = CIPHER_REGION_SIZE if bs > LARGE_FILE_THRESHOLD else bs
        sized.append((cl, bs, f))
    if not sized:
        print("[!] no usable files"); sys.exit(2)
    sized.sort(reverse=True)
    _cl, bs, first = sized[0]
    fb = open(os.path.join(args.in_dir, first), 'rb').read()[len(MAGIC):]
    kbody = fb[bs - CIPHER_REGION_SIZE:] if bs > LARGE_FILE_THRESHOLD else fb
    t0 = time.time()
    cands = find_tea_key(kbody, keyspace, top_n=3)
    if not cands:
        print("[!] no TEA key candidate (different build/keyspace?)"); sys.exit(2)
    KEY = cands[0][2]
    print(f"[+] TEA key {KEY.hex()}  ({time.time()-t0:.1f}s)")

    known = args.known_size if (args.known_size and os.path.isdir(args.known_size)) else None
    os.makedirs(args.out_dir, exist_ok=True)

    # --- Pass 1: decrypt + single-file blind framing ---
    recs = {}      # fn -> dict(content, conf, out)
    anchors = []   # high-confidence contents (for cross-file alignment)
    pending = []
    for fn in hd_files:
        raw = open(os.path.join(args.in_dir, fn), 'rb').read()
        if not raw.startswith(MAGIC):
            recs[fn] = None; continue
        body = raw[len(MAGIC):]
        out_name = fn[:-3]
        if len(body) > LARGE_FILE_THRESHOLD:
            content = large_file_content(body, KEY)
            recs[fn] = dict(content=content, conf='det', out=out_name)
            anchors.append(content); continue
        pt = recover_pt(body, KEY)
        if known:   # validation mode: exact prefix from original size
            base = fn[:-3]; op = os.path.join(known, base)
            if os.path.isfile(op):
                pref = len(pt) - os.path.getsize(op) - TRAIL_PAD
                pref = pref if 3 <= pref <= 10 else blind_prefix_single(pt, fn)[0]
            else:
                pref = blind_prefix_single(pt, fn)[0]
            content = pt[pref:len(pt) - TRAIL_PAD]
            recs[fn] = dict(content=content, conf='known', out=out_name); continue
        pref, sc, margin = blind_prefix_single(pt, fn)
        content = pt[pref:len(pt) - TRAIL_PAD]
        if sc >= DECISIVE and margin > 0:
            recs[fn] = dict(content=content, conf='high', out=out_name)
            anchors.append(content)
        else:
            recs[fn] = dict(content=content, conf='low', out=out_name, pt=pt)
            pending.append(fn)

    # --- Pass 2: cross-file alignment for low-confidence files ---
    aligned = 0
    for fn in pending:
        r = recs[fn]
        pref, ok = cross_file_align(r['pt'], anchors)
        if ok:
            r['content'] = r['pt'][pref:len(r['pt']) - TRAIL_PAD]
            r['conf'] = 'aligned'; aligned += 1

    # --- write outputs ---
    high = det = low = 0
    for fn in hd_files:
        r = recs.get(fn)
        if not r: continue
        open(os.path.join(args.out_dir, r['out']), 'wb').write(r['content'])
        c = r['conf']
        if c in ('det', 'high', 'known', 'aligned'): high += 1
        else: low += 1
        if c == 'low':
            print(f"  [?] {fn}: low-confidence framing (unique high-entropy, no magic/peer) -- verify manually")
    print("=" * 70)
    print(f"Recovered {sum(1 for f in hd_files if recs.get(f))}/{len(hd_files)}  "
          f"(confident {high}, low-confidence {low}, aligned {aligned})")
    print(f"Output: {args.out_dir}")
    print("=" * 70)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[interrupted]")
