#!/usr/bin/env python3
"""Independent re-verification of every RC-01..RC-03 match in the corpus.

The paper claims each surviving RSA private-key case is independently checkable
against the captured material.  This script makes good on that claim WITHOUT
using any pipeline code: it reads the raw memory snapshots the capture retained,
parses the key structures here, and checks the arithmetic.

  CAPI  PRIVATEKEYBLOB   -> parse N, P, Q   -> assert N == P*Q
  BCRYPT RSAFULLPRIVATE  -> parse N, P, Q   -> assert N == P*Q
  wanakiwi prime window  -> read candidate p -> assert N mod p == 0, p != N

Writes rsa_verification.json next to this script.
"""
from __future__ import annotations
import os, sys, json, glob, collections

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from tracemap import build, load_samples  # noqa: E402

# Neither the extracted joins nor the raw traces are shipped with the artifact;
# point these at local copies to re-run the verification.
EXTRACTED = os.environ.get("RANSACK_EXTRACTED", "")
TRACE_ROOT = os.environ.get("RANSACK_TRACE_ROOT", "")
OUT = os.path.join(HERE, "rsa_verification.json")

RSA_CASES = {"RC-01", "RC-02", "RC-03"}


# --------------------------------------------------------------------------
# key-structure parsers (written here on purpose: an independent check)
# --------------------------------------------------------------------------
def parse_capi_privatekeyblob(buf, off):
    """MS PRIVATEKEYBLOB, little-endian throughout.
    BLOBHEADER(8) RSAPUBKEY(magic4 bitlen4 pubexp4) modulus[n/8]
    prime1[n/16] prime2[n/16] ... -> (N, P, Q) or None."""
    if len(buf) < off + 20:
        return None
    if buf[off:off + 4] != b"\x07\x02\x00\x00" and buf[off] != 0x07:
        return None
    if buf[off + 8:off + 12] != b"RSA2":
        return None
    bitlen = int.from_bytes(buf[off + 12:off + 16], "little")
    if not (256 <= bitlen <= 16384) or bitlen % 16:
        return None
    nb, pb = bitlen // 8, bitlen // 16
    need = 20 + nb + 2 * pb
    if len(buf) < off + need:
        return None
    p0 = off + 20
    N = int.from_bytes(buf[p0:p0 + nb], "little")
    P = int.from_bytes(buf[p0 + nb:p0 + nb + pb], "little")
    Q = int.from_bytes(buf[p0 + nb + pb:p0 + nb + 2 * pb], "little")
    return (N, P, Q) if N and P and Q else None


def parse_bcrypt_rsafullprivate(buf, off):
    """BCRYPT_RSAKEY_BLOB header is little-endian; the numbers are BIG-endian.
    magic4 BitLength4 cbPublicExp4 cbModulus4 cbPrime1 4 cbPrime2 4
    then Exponent, Modulus, Prime1, Prime2 -> (N, P, Q) or None."""
    if len(buf) < off + 24:
        return None
    magic = buf[off:off + 4]
    if magic not in (b"RSA3", b"RSA2"):           # FULLPRIVATE / PRIVATE
        return None
    cbExp = int.from_bytes(buf[off + 8:off + 12], "little")
    cbMod = int.from_bytes(buf[off + 12:off + 16], "little")
    cbP1 = int.from_bytes(buf[off + 16:off + 20], "little")
    cbP2 = int.from_bytes(buf[off + 20:off + 24], "little")
    if not (32 <= cbMod <= 2048) or not cbP1 or not cbP2 or cbExp > 16:
        return None
    s = off + 24
    need = cbExp + cbMod + cbP1 + cbP2
    if len(buf) < s + need:
        return None
    s += cbExp
    N = int.from_bytes(buf[s:s + cbMod], "big"); s += cbMod
    P = int.from_bytes(buf[s:s + cbP1], "big"); s += cbP1
    Q = int.from_bytes(buf[s:s + cbP2], "big")
    return (N, P, Q) if N and P and Q else None


def read_int(buf, off, nbytes, endian):
    if off < 0 or off + nbytes > len(buf):
        return None
    return int.from_bytes(buf[off:off + nbytes], endian)


# --------------------------------------------------------------------------
def snapshot_path(trace, proc, fname):
    p = os.path.join(TRACE_ROOT, trace, f"proc_{proc}", fname)
    return p if os.path.exists(p) else None


def verify_trace(trace, proc, bs):
    """Return a per-capture verification record."""
    rec = {"blobs_checked": 0, "blobs_ok": 0, "blob_fail": [],
           "public_blobs": 0,
           "primes_checked": 0, "primes_ok": 0, "prime_fail": [],
           "moduli": []}
    cache = {}

    def load(fn):
        if fn not in cache:
            p = snapshot_path(trace, proc, fn)
            cache[fn] = open(p, "rb").read() if p else None
        return cache[fn]

    moduli = set()
    for key, parser in (("capi_rsa_blob_hits", parse_capi_privatekeyblob),
                        ("cryptoapi_rsa_blob_hits", parse_capi_privatekeyblob),
                        ("bcrypt_rsa_blob_hits", parse_bcrypt_rsafullprivate)):
        for h in (bs.get(key) or []):
            # A public blob (BCRYPT RSA1) carries no primes, so N == P*Q is not
            # a check it can satisfy.  Count it, do not score it.
            if h.get("is_private") is False:
                rec["public_blobs"] += 1
                continue
            buf = load(h.get("snapshot_file") or "")
            if buf is None:
                continue
            rec["blobs_checked"] += 1
            got = parser(buf, int(h.get("offset") or 0))
            if got and got[0] == got[1] * got[2]:
                rec["blobs_ok"] += 1
                moduli.add(got[0])
            else:
                rec["blob_fail"].append({"snap": h.get("snapshot_file"),
                                         "off": h.get("offset"),
                                         "parsed": bool(got)})

    for h in (bs.get("wanakiwi_prime_hits") or []):
        buf = load(h.get("snapshot_file") or "")
        if buf is None:
            continue
        nb = int(h.get("prime_bytes") or 0)
        endian = "little" if (h.get("endian") or "little") == "little" else "big"
        cand = read_int(buf, int(h.get("offset") or 0), nb, endian)
        if not cand:
            continue
        rec["primes_checked"] += 1
        if any(N % cand == 0 and cand != N for N in moduli):
            rec["primes_ok"] += 1
        else:
            rec["prime_fail"].append({"snap": h.get("snapshot_file"),
                                      "off": h.get("offset"),
                                      "have_modulus": bool(moduli)})
    rec["moduli"] = len(moduli)
    return rec


def main():
    if not TRACE_ROOT:
        raise SystemExit(
            "the raw traces are not part of this artifact; set "
            "RANSACK_TRACE_ROOT to a directory of trace_* directories to "
            "re-run this verification. The recorded result is in "
            "rsa_verification.json")
    t2r, recs, unjoined, ambiguous = build()
    assert not unjoined and not ambiguous

    def rcset(r):
        v = r["RC mapping"].strip()
        return set() if not v else {"RC-" + t.strip() for t in v.split(",") if t.strip()}

    # paper population: validated captures that match an RSA case
    targets = {}
    for t, r in t2r.items():
        if r["execution_outcome"] != "Captured evidence":
            continue
        if r["File-encryption validated"].strip().lower() != "o":
            continue
        if not (rcset(r) & RSA_CASES):
            continue
        targets.setdefault(id(r), {"rec": r, "traces": []})["traces"].append(t)

    print(f"RSA-case captures (validated): {len(targets)}")

    out = {"n_samples": len(targets), "samples": [], "totals": collections.Counter()}
    for rid, info in sorted(targets.items(), key=lambda kv: kv[1]["rec"]["sample"]):
        r = info["rec"]
        agg = {"sample": r["sample"], "family": r["_fam"],
               "rc": sorted(rcset(r) & RSA_CASES),
               "blobs_checked": 0, "blobs_ok": 0, "public_blobs": 0,
               "primes_checked": 0, "primes_ok": 0, "moduli": 0, "fails": []}
        for t in info["traces"]:
            f = os.path.join(EXTRACTED, t + ".json")
            if not os.path.exists(f):
                continue
            try:
                procs = json.load(open(f, encoding="utf-8"))
            except Exception:
                continue
            for pid, d in (procs or {}).items():
                if not d:
                    continue
                v = verify_trace(t, pid, d.get("byte_signatures") or {})
                for k in ("blobs_checked", "blobs_ok", "public_blobs",
                          "primes_checked", "primes_ok"):
                    agg[k] += v[k]
                agg["moduli"] += v["moduli"]
                agg["fails"].extend(v["blob_fail"][:3] + v["prime_fail"][:3])
        agg["verified"] = (agg["blobs_ok"] > 0) or (agg["primes_ok"] > 0)
        out["samples"].append(agg)
        out["totals"]["blobs_checked"] += agg["blobs_checked"]
        out["totals"]["blobs_ok"] += agg["blobs_ok"]
        out["totals"]["primes_checked"] += agg["primes_checked"]
        out["totals"]["primes_ok"] += agg["primes_ok"]
        out["totals"]["public_blobs"] += agg["public_blobs"]
        out["totals"]["public_only"] += (agg["blobs_ok"] == 0 and agg["primes_ok"] == 0
                                         and agg["public_blobs"] > 0)
        out["totals"]["samples_verified"] += bool(agg["verified"])

    out["totals"] = dict(out["totals"])
    json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)

    T = out["totals"]
    print(f"\nblobs  N == P*Q : {T.get('blobs_ok',0)} / {T.get('blobs_checked',0)}")
    print(f"primes N mod p   : {T.get('primes_ok',0)} / {T.get('primes_checked',0)}")
    print(f"samples verified : {T.get('samples_verified',0)} / {out['n_samples']}")
    bad = [s for s in out["samples"] if not s["verified"]]
    print(f"\nunverified samples: {len(bad)}")
    for s in bad[:15]:
        print(f"   {s['family']:18} {s['sample']:26} {','.join(s['rc'])}"
              f"  blobs={s['blobs_ok']}/{s['blobs_checked']}"
              f" primes={s['primes_ok']}/{s['primes_checked']}")
    print(f"\n[+] {OUT}")


if __name__ == "__main__":
    main()
