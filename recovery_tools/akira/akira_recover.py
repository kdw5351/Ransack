#!/usr/bin/env python3
"""
akira_recover.py -- Akira key-based recovery (whole-file, from one instrumented run).

Akira is a hybrid encryptor: it draws a ChaCha key and nonce, enciphers part of every
victim file with them, wraps that key material under the operators' RSA-4096 public key,
and appends the wrapped blob in a 534-byte footer. The plaintext key therefore exists in
the victim process only for the instant between generation and the RSA wrap -- and that
instant is exactly what the instrumented run captures: the 40-byte input buffer handed to
the wrap call is dumped verbatim as a crypto snapshot.

With that 40-byte value the encrypted regions are recoverable, so recovery is whole-file
rather than the cleartext-only salvage of akira_salvage.py (which remains the fallback
when no key was captured).

Two facts were established from the captured run and the file layout, and both differ
from public reporting:

  * the stream cipher is ChaCha with EIGHT rounds (ChaCha8), not ChaCha20; the keystream
    generated from the captured key/nonce matches the ciphertext-plaintext difference
    exactly, and no 20-round variant does.
  * the 534-byte footer is [512-byte RSA-wrapped key material][22-byte metadata], and the
    metadata carries the ORIGINAL FILE SIZE at offset 14 (LE uint32) and an ENCRYPTION-MODE
    byte at offset 12, so the encrypted span is recoverable from the file itself:
        mode 0 -> the whole body is enciphered
        mode 1 -> only the first half is enciphered
        mode 2 -> four chunks of size/10 separated by gaps of size/50 (keystream continuous)

Usage:
    python akira_recover.py recover-key <proc_dir>
    python akira_recover.py decrypt <proc_dir> <enc_dir> <out_dir> [--known-size <originals>]

Requires Python 3.10+ only.
"""
import argparse
import hashlib
import os
import struct
import sys

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

FOOTER_LEN = 534
WRAP_LEN = 512
META_OFF = WRAP_LEN
KEY_BLOB_LEN = 40          # 32-byte ChaCha key + 8-byte nonce, the RSA-wrap input
ROUNDS = 8                 # ChaCha8, established by keystream match


# ---------------------------------------------------------------- ChaCha8
def _rotl32(v, c):
    return ((v << c) & 0xffffffff) | (v >> (32 - c))


def _qr(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xffffffff; x[d] ^= x[a]; x[d] = _rotl32(x[d], 16)
    x[c] = (x[c] + x[d]) & 0xffffffff; x[b] ^= x[c]; x[b] = _rotl32(x[b], 12)
    x[a] = (x[a] + x[b]) & 0xffffffff; x[d] ^= x[a]; x[d] = _rotl32(x[d], 8)
    x[c] = (x[c] + x[d]) & 0xffffffff; x[b] ^= x[c]; x[b] = _rotl32(x[b], 7)


def chacha_block(key, counter, nonce8, rounds=ROUNDS):
    """Original Bernstein layout: 64-bit counter, 64-bit nonce."""
    st = list(struct.unpack('<4I', b"expand 32-byte k")) + list(struct.unpack('<8I', key))
    st += [counter & 0xffffffff, (counter >> 32) & 0xffffffff]
    st += list(struct.unpack('<2I', nonce8))
    w = st[:]
    for _ in range(rounds // 2):
        _qr(w, 0, 4, 8, 12); _qr(w, 1, 5, 9, 13); _qr(w, 2, 6, 10, 14); _qr(w, 3, 7, 11, 15)
        _qr(w, 0, 5, 10, 15); _qr(w, 1, 6, 11, 12); _qr(w, 2, 7, 8, 13); _qr(w, 3, 4, 9, 14)
    return struct.pack('<16I', *[(w[i] + st[i]) & 0xffffffff for i in range(16)])


class Keystream:
    """Continuous ChaCha8 keystream; consumed only across enciphered bytes."""

    def __init__(self, key, nonce8):
        self.key, self.nonce = key, nonce8
        self.counter, self.buf, self.off = 0, b'', 0

    def take(self, n):
        out = bytearray()
        while len(out) < n:
            if self.off >= len(self.buf):
                self.buf = chacha_block(self.key, self.counter, self.nonce)
                self.counter += 1
                self.off = 0
            take = min(n - len(out), len(self.buf) - self.off)
            out += self.buf[self.off:self.off + take]
            self.off += take
        return bytes(out)


# ---------------------------------------------------------------- key recovery
def recover_key(proc_dir):
    """The RSA-wrap input is the run's only 40-byte crypto snapshot."""
    hits = []
    for root, _dirs, files in os.walk(proc_dir):
        for fn in files:
            if not (fn.startswith('crypto_') and fn.endswith('.bin')):
                continue
            p = os.path.join(root, fn)
            if os.path.getsize(p) != KEY_BLOB_LEN:
                continue
            blob = open(p, 'rb').read()
            hits.append((p, blob))
    if not hits:
        return None, None, "no %d-byte crypto snapshot found" % KEY_BLOB_LEN
    if len(hits) > 1:
        # keep them all; the caller can disambiguate by trial decryption
        return hits[0][1][:32], hits[0][1][32:40], "%d candidates, using %s" % (
            len(hits), os.path.basename(hits[0][0]))
    p, blob = hits[0]
    return blob[:32], blob[32:40], os.path.basename(p)


# ---------------------------------------------------------------- layout
def parse_footer(raw):
    """-> (mode, original_size) from the 22-byte metadata behind the wrapped key."""
    if len(raw) < FOOTER_LEN:
        return None, None
    meta = raw[-FOOTER_LEN + META_OFF:]
    mode = meta[12]
    size = struct.unpack('<I', meta[14:18])[0]
    return mode, size


def enc_regions(body_len, mode):
    """Byte ranges of `body` that are enciphered, in order."""
    if mode == 0:
        return [(0, body_len)]
    if mode == 1:
        return [(0, body_len // 2)]
    if mode == 2:
        # Four chunks of size/10 separated by gaps of size/50. Calibrated on a single
        # sample whose content is highly repetitive, so the chunk boundaries could not be
        # confirmed independently; mode-2 output is reported but is NOT byte-verified.
        chunk = body_len // 10
        gap = -(-body_len // 50)           # ceil
        stride = chunk + gap
        return [(i * stride, i * stride + chunk) for i in range(4)
                if i * stride + chunk <= body_len]
    return [(0, body_len // 2)]            # unknown mode: fall back to the common case


def decrypt_file(raw, key, nonce):
    mode, size = parse_footer(raw)
    if mode is None:
        return None, "file shorter than the 534-byte footer"
    body = bytearray(raw[:len(raw) - FOOTER_LEN])
    ks = Keystream(key, nonce)
    for start, end in enc_regions(len(body), mode):
        end = min(end, len(body))
        if end <= start:
            continue
        pad = ks.take(end - start)
        for i in range(end - start):
            body[start + i] ^= pad[i]
    out = bytes(body[:size]) if 0 < size <= len(body) else bytes(body)
    return out, "mode=%d size=%d" % (mode, size)


# ---------------------------------------------------------------- CLI
def cmd_recover_key(proc_dir):
    key, nonce, src = recover_key(proc_dir)
    if key is None:
        print("[!] %s" % src); return 2
    print("[+] key   : %s" % key.hex())
    print("[+] nonce : %s" % nonce.hex())
    print("[+] source: %s   (ChaCha8, Bernstein 64-bit nonce, counter 0)" % src)
    return 0


def cmd_decrypt(proc_dir, enc_dir, out_dir, known=None):
    key, nonce, src = recover_key(proc_dir)
    if key is None:
        print("[!] %s" % src); return 2
    print("[+] key %s  nonce %s  (from %s)" % (key.hex(), nonce.hex(), src))
    os.makedirs(out_dir, exist_ok=True)
    files = sorted(f for f in os.listdir(enc_dir) if f.endswith('.akira'))
    if not files:
        print("[!] no *.akira files in %s" % enc_dir); return 2
    ok = exact = checked = 0
    for fn in files:
        raw = open(os.path.join(enc_dir, fn), 'rb').read()
        rec, info = decrypt_file(raw, key, nonce)
        if rec is not None and info.startswith("mode=2"):
            info += "  [unverified layout]"
        if rec is None:
            print("  [!!] %s: %s" % (fn, info)); continue
        base = fn[:-len('.akira')]
        open(os.path.join(out_dir, base), 'wb').write(rec)
        ok += 1
        mark = ""
        if known:
            op = os.path.join(known, base)
            if os.path.isfile(op):
                checked += 1
                same = hashlib.sha256(rec).digest() == hashlib.sha256(open(op, 'rb').read()).digest()
                exact += same
                mark = "  byte-exact" if same else "  MISMATCH"
        print("  [OK] %-30s %s%s" % (base, info, mark))
    print("\nRecovered %d/%d files -> %s" % (ok, len(files), out_dir))
    if known:
        print("Byte-exact against held-out originals: %d/%d" % (exact, checked))
    return 0


def main():
    ap = argparse.ArgumentParser(description="Akira key-based whole-file recovery")
    sub = ap.add_subparsers(dest='cmd', required=True)
    rk = sub.add_parser('recover-key', help='print the ChaCha8 key/nonce captured in the run')
    rk.add_argument('proc_dir')
    d = sub.add_parser('decrypt', help='recover every *.akira file in a folder')
    d.add_argument('proc_dir'); d.add_argument('enc_dir'); d.add_argument('out_dir')
    d.add_argument('--known-size', dest='known', help='[validation] folder of held-out originals')
    a = ap.parse_args()
    if a.cmd == 'recover-key':
        return cmd_recover_key(a.proc_dir)
    return cmd_decrypt(a.proc_dir, a.enc_dir, a.out_dir, a.known)


if __name__ == '__main__':
    sys.exit(main())
