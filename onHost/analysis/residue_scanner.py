"""Scan key-birth memory snapshots for captured key bytes.

Paper §III specifies the {NONE, LOW, MID, HIGH} tier scheme with three axes
(absolute-count, unique-tag, ratio).  Tier cutoffs are not published by the
paper; _classify() uses the minimum spec-grounded rules (see its docstring).

Inputs (from `loaders.load_bundle`):
  bundle["keybirth_snapshots"]   parsed key_residue_snapshots.jsonl rows
  bundle["crypto_events"]        for the captured-key inventory
  trace_dir                       to read each `snapshot_file` from disk
"""

# Note (evidence independence, paper section 4.3.2):
# When the scanner promotes residue_class via byte_sig corroboration,
# the original (un-promoted) class is preserved at
# result['byte_sig_promotion']['from'] so RC-02/03/06/07 (and any other
# consumer that requires independent evidence) can read the un-promoted value,
# and each RC's residue_class_at_least(allowed_byte_sigs=...) reverts a
# promotion driven by an irrelevant signature. See analyze_trace.py for the
# promotion call site; this contract addresses the double-counting
# concern.
from __future__ import annotations

import os
from collections import Counter


def _captured_keys(crypto_events: list[dict]) -> list[dict]:
    """Pull every distinct key-shaped bytes blob from in_buf_hex /
    out_buf_hex on rand / keygen / kdf / key_import / key_export events.

    NOTE (data-availability): the shipped PinTool emits in_buf/out_buf as
    POINTER addresses, not *_hex content, so under the current feed this
    literal scan returns [] and scan() reports residue_class=NONE. The
    ACTIVE residue path is apply_byte_sig_promotion() below (byte-signature
    scanners over the crypto_<N>.bin key-birth dumps). This literal scan is
    kept as the corroborating axis for any future feed that does carry
    key-byte content; it is not currently load-bearing.
    """
    out: list[dict] = []
    seen: set[str] = set()
    for ev in crypto_events:
        kind = ev.get("kind")
        if kind not in ("rand", "keygen", "kdf", "key_import", "key_export"):
            continue
        for field in ("in_buf_hex", "out_buf_hex"):
            hexstr = ev.get(field)
            if not hexstr or len(hexstr) < 16:
                continue
            if hexstr in seen:
                continue
            seen.add(hexstr)
            try:
                raw = bytes.fromhex(hexstr)
            except ValueError:
                continue
            # 8-byte minimum: P(spurious collision in 16 KB region) =
            # 16376 / 2^64 ≈ 8.9e-16, negligible.
            if len(raw) < 8:
                continue
            out.append({
                "hex":      hexstr,
                "bytes":    raw,
                "api":      ev.get("api"),
                "kind":     kind,
                "source":   field,
                "call_id":  ev.get("call_id"),
                "loop_id":  ev.get("loop_id"),
                "tag":      ev.get("call_id"),  # call_id acts as the tag
            })
    return out


def _read_snapshot_bytes(trace_dir: str, rel_path: str) -> bytes:
    # path-traversal hardening.
    # rel_path comes from crypto_events_*.jsonl, which is emitted by the
    # PinTool on the analysis VM and could in principle contain '..' or an
    # absolute path. We resolve both trace_dir and the joined path through
    # realpath() and require the result to remain inside trace_dir; any
    # absolute rel_path or traversal escape returns b'' (treated as
    # 'snapshot not available') rather than reading from outside the trace
    # sandbox.
    if not rel_path or os.path.isabs(rel_path):
        return b""
    abs_base = os.path.realpath(trace_dir)
    abs_p = os.path.realpath(os.path.join(trace_dir, rel_path))
    # Require abs_p to be a sub-path of abs_base.  os.sep guard avoids the
    # classic prefix-collision (e.g. /trace and /trace_alt).
    if not (abs_p == abs_base or abs_p.startswith(abs_base + os.sep)):
        return b""
    if not os.path.isfile(abs_p):
        return b""
    with open(abs_p, "rb") as f:
        return f.read()


def _classify(matches: int, unique_tags: int, total_tags: int) -> str:
    """Spec-grounded tier assignment (paper §III axes, no unpublished cutoffs).

    Rules derived directly from §4.3's three axes:
      * Any match at all          → at least LOW.
      * unique_tags >= 2          → at least MID  (two independent call-sites
                                    is the minimum non-trivial corroboration
                                    on the distinct-evidence axis).
      * unique_tags == total_tags and total_tags >= 2
                                  → HIGH (every tagged call-site confirmed;
                                    ratio == 1.0 is the strongest ratio signal).
    """
    if matches <= 0:
        return "NONE"
    if total_tags >= 2 and unique_tags == total_tags:
        return "HIGH"
    if unique_tags >= 2:
        return "MID"
    return "LOW"


def scan(bundle: dict) -> dict:
    """Run the residue scan. Returns:

        {
          "residue_class":         "HIGH" | "MID" | "LOW" | "NONE",
          "total_matches":         N,
          "unique_tags_with_hit":  N,
          "total_captured_keys":   N,
          "snapshots_scanned":     N,
          "matches_per_snapshot":  {file: count},
          "matches_per_tag":       {call_id: count},
          "first_hit_per_tag":     {call_id: {file, offset}},
        }

    Returns class NONE when scanner cannot run (no keys or no snapshots).
    """
    snaps = bundle.get("keybirth_snapshots") or []
    crypto = bundle.get("crypto_events") or []
    trace_dir = bundle["trace_dir"]

    keys = _captured_keys(crypto)
    if not keys or not snaps:
        return {
            "residue_class":        "NONE",
            "total_matches":         0,
            "unique_tags_with_hit":  0,
            "total_captured_keys":   len(keys),
            "snapshots_scanned":     len(snaps),
            "matches_per_snapshot":  {},
            "matches_per_tag":       {},
            "first_hit_per_tag":     {},
            "note":                  "no captured keys or no snapshots",
        }

    matches_per_snapshot: Counter = Counter()
    matches_per_tag:      Counter = Counter()
    first_hit_per_tag:    dict[int, dict] = {}
    snapshots_scanned = 0

    for snap_meta in snaps:
        rel = snap_meta.get("snapshot_file")
        if not rel:
            continue
        data = _read_snapshot_bytes(trace_dir, rel)
        if not data:
            continue
        snapshots_scanned += 1
        for k in keys:
            needle = k["bytes"]
            # find every occurrence; bytes.find is linear-search, fine for
            # 16 KB regions and a few hundred candidate keys.
            offset = data.find(needle)
            if offset < 0:
                continue
            count = 1
            while True:
                nxt = data.find(needle, offset + 1)
                if nxt < 0:
                    break
                count += 1
                offset = nxt
            matches_per_snapshot[rel] += count
            matches_per_tag[k["tag"]] += count
            first_hit_per_tag.setdefault(k["tag"], {
                "file":   rel,
                "offset": data.find(needle),
                "api":    k["api"],
                "kind":   k["kind"],
            })

    total_matches = sum(matches_per_tag.values())
    unique_tags = len(matches_per_tag)
    total_tags = len({k["tag"] for k in keys if k["tag"] is not None})
    cls = _classify(total_matches, unique_tags, total_tags)

    return {
        "residue_class":        cls,
        "total_matches":        total_matches,
        "unique_tags_with_hit": unique_tags,
        "total_captured_keys":  len(keys),
        "total_tags":           total_tags,
        "snapshots_scanned":    snapshots_scanned,
        "matches_per_snapshot": dict(matches_per_snapshot.most_common()),
        "matches_per_tag":      dict(matches_per_tag),
        "first_hit_per_tag":    first_hit_per_tag,
    }


# Byte-signature promotion (paper §III): when the literal key scan produces
# NONE (PinTool did not emit out_buf_hex), published algorithm hits still
# prove key material in heap and promote the tier to HIGH:
#   aeskeyfind (Halderman 2008) — 240-byte FIPS-197 round-key schedule
#   wanakiwi   (Guinet 2017)    — RSA prime divisor of captured modulus N
#   bcrypt_priv (MS CNG bcrypt.h) — BCRYPT_RSAPRIVATE_BLOB in heap
#   cryptoapi_priv  (MS CryptoAPI)   — CryptoAPI PRIVATEKEYBLOB (legacy; magic at +8 after BLOBHEADER)
#   avaddon     (Yuste 2021)    — key_data_s 12-byte pattern + pointer
_CLASS_ORDER = {"NONE": 0, "LOW": 1, "MID": 2, "HIGH": 3}
_CLASS_BY_ORDER = ["NONE", "LOW", "MID", "HIGH"]


def apply_byte_sig_promotion(residue: dict, byte_sigs: dict) -> dict:
    """Promote residue class if any published byte-signature scanner hit."""
    if not residue or not byte_sigs:
        return residue
    current = (residue.get("residue_class") or "NONE").upper()
    cur_rank = _CLASS_ORDER.get(current, 0)
    new_rank = cur_rank
    reasons: list[str] = []

    aes_hits     = int(byte_sigs.get("aeskeyfind_count") or 0)
    wana_hits    = int(byte_sigs.get("wanakiwi_prime_count") or 0)
    avaddon_hits = int(byte_sigs.get("avaddon_session_count") or 0)
    bcrypt_priv = sum(1 for h in (byte_sigs.get("bcrypt_rsa_blob_hits") or [])
                       if h.get("is_private"))
    # CryptoAPI PRIVATEKEYBLOB (legacy CryptoAPI) is a directly-recoverable
    # private RSA key just like the BCRYPT form -- bcrypt_rsa_blob_scan
    # cannot see it because the magic sits after an 8-byte BLOBHEADER.
    cryptoapi_priv = sum(1 for h in (byte_sigs.get("cryptoapi_rsa_blob_hits") or [])
                     if h.get("is_private"))

    # All five byte-signature scanners promote to HIGH on hit -- each
    # detects directly-recoverable key material in heap. See module
    # comment block above for the per-scanner rationale.
    # Each scanner is recorded INDEPENDENTLY: a hit always appends its reason
    # and lifts the rank to at least HIGH. Do NOT gate on `new_rank < HIGH` --
    # that made promotion order-dependent (whichever scanner fired first
    # claimed HIGH and the rest were dropped from `reasons`), so an RC whose
    # allowed_byte_sigs listed only a dropped scanner would wrongly fail even
    # though that key material was present (e.g. a CryptoAPI private blob masked by
    # a wanakiwi-prime hit on the same dump).
    if aes_hits > 0:
        new_rank = max(new_rank, _CLASS_ORDER["HIGH"])
        reasons.append(f"aeskeyfind:{aes_hits}")
    if wana_hits > 0:
        new_rank = max(new_rank, _CLASS_ORDER["HIGH"])
        reasons.append(f"wanakiwi_prime:{wana_hits}")
    if bcrypt_priv > 0:
        new_rank = max(new_rank, _CLASS_ORDER["HIGH"])
        reasons.append(f"bcrypt_rsa_blob:{bcrypt_priv}")
    if cryptoapi_priv > 0:
        new_rank = max(new_rank, _CLASS_ORDER["HIGH"])
        reasons.append(f"cryptoapi_rsa_blob:{cryptoapi_priv}")
    if avaddon_hits > 0:
        new_rank = max(new_rank, _CLASS_ORDER["HIGH"])
        reasons.append(f"avaddon:{avaddon_hits}")

    if new_rank > cur_rank:
        residue = dict(residue)
        residue["residue_class"] = _CLASS_BY_ORDER[new_rank]
        residue["byte_sig_promotion"] = {
            "from":    current,
            "to":      _CLASS_BY_ORDER[new_rank],
            "reasons": reasons,
        }
    return residue
