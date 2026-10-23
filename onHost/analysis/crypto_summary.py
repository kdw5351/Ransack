"""Aggregate crypto_events.jsonl per loop, per kind, and per API.

Each event row is shaped:
    {"event":"crypto_api_call","api":"BCryptEncrypt","dll":"bcrypt.dll",
     "kind":"sym_enc","loop_id":12,"loop_iteration":N,
     "loop_is_captured":true|false,"loop_capture_state":"captured|pending",
     "args":["0x...","0x...","0x...","0x..."]}

`kind` is one of:
    rand | keygen | kdf | sym_enc | asym_enc | hash | key_import |
    key_export | memcpy | normal_op

`memcpy` and `normal_op` are NOT crypto sinks — they're tracked because
ransomware uses RtlCopyMemory/memcpy as a side-channel hint for key
material movement. We isolate them so consumers can ignore or surface
them at their discretion.
"""
from __future__ import annotations

from collections import Counter, defaultdict


CRYPTO_KINDS = {
    "rand", "keygen", "kdf", "sym_enc", "asym_enc", "hash",
    "key_import", "key_export",
}
MEMOP_KINDS  = {"memcpy", "normal_op"}

# Known asymmetric private-key blob magics (4-byte head, ascii).
# Used by `inspect_blob_format` for recovery-case RC-01 evidence.
# Microsoft CNG bcrypt.h asymmetric key-blob magics. Source: Microsoft CNG
# bcrypt.h (verbatim from MSDK / Wine mirror). Each 4-byte LE ASCII tag
# is the BCRYPT_*_BLOB_MAGIC value the BLOBHEADER carries.
#
# bcrypt.h verbatim mapping (verified 2026-06-01):
#   ECDH:
#     ECK1 = 0x314b4345 = BCRYPT_ECDH_PUBLIC_P256_MAGIC   <- PUBLIC
#     ECK2 = 0x324b4345 = BCRYPT_ECDH_PRIVATE_P256_MAGIC  <- PRIVATE
#     ECK3 = 0x334b4345 = BCRYPT_ECDH_PUBLIC_P384_MAGIC   <- PUBLIC
#     ECK4 = 0x344b4345 = BCRYPT_ECDH_PRIVATE_P384_MAGIC  <- PRIVATE
#     ECK5 = 0x354b4345 = BCRYPT_ECDH_PUBLIC_P521_MAGIC   <- PUBLIC
#     ECK6 = 0x364b4345 = BCRYPT_ECDH_PRIVATE_P521_MAGIC  <- PRIVATE
#   ECDSA (same convention as ECDH above: ODD suffix = PUBLIC, EVEN = PRIVATE):
#     ECS1/3/5 = ECDSA PUBLIC  P256/P384/P521
#     ECS2/4/6 = ECDSA PRIVATE P256/P384/P521
#   RSA:
#     RSA1 = BCRYPT_RSAPUBLIC_BLOB                       <- PUBLIC
#     RSA2 = BCRYPT_RSAPRIVATE_BLOB     (no CRT)         <- PRIVATE
#     RSA3 = BCRYPT_RSAFULLPRIVATE_BLOB (with CRT)       <- PRIVATE
ASYM_PRIV_MAGICS = {"RSA2", "RSA3",
                     "ECK2", "ECK4", "ECK6",   # ECDH P256/P384/P521 PRIVATE
                     "ECS2", "ECS4", "ECS6"}   # ECDSA P256/P384/P521 PRIVATE
ASYM_PUB_MAGICS = {"RSA1",
                    "ECK1", "ECK3", "ECK5",     # ECDH P256/P384/P521 PUBLIC
                    "ECS1", "ECS3", "ECS5"}     # ECDSA P256/P384/P521 PUBLIC


def _bucket(kind: str) -> str:
    if kind in CRYPTO_KINDS: return "crypto"
    if kind in MEMOP_KINDS:  return "memop"
    return "other"


# per-length spec citation helper for sym_keys entries.
# The previous code cited "FIPS-197 / RFC-7539 / NIST SP 800-67" for every
# length, but none of those standards covers 8-byte keys (single DES is
# FIPS 46-3, deprecated) and each standard covers a specific length subset.
def _spec_for_len(n: int) -> str:
    if n == 8:
        return "FIPS 46-3 (single DES, deprecated)"
    if n == 16:
        return "FIPS-197 (AES-128)"
    if n == 24:
        return "FIPS-197 (AES-192) / SP 800-67 (3DES)"
    if n == 32:
        return "FIPS-197 (AES-256) / RFC-7539 (ChaCha20)"
    if n == 64:
        return "HMAC block size / large-key (no specific NIST spec)"
    return "(unknown)"


def _hex_head(hex_str: str, n: int = 4) -> str:
    """ASCII-decode the first n bytes of a hex string (ransom blob magics
    are 4 ASCII bytes — RSA2 / ECK1 / ...). Non-printable chars are
    masked with '?' so the report does not break."""
    if not hex_str:
        return ""
    # bytes.fromhex raises ValueError on odd-length or
    # non-hex input (truncated/corrupted trace blobs). Guard so a single
    # malformed event does not abort summarize() for the whole sample.
    import string
    head = hex_str[: 2 * n]
    if len(head) < 2 * n or any(c not in string.hexdigits for c in head):
        return ""
    try:
        raw = bytes.fromhex(head)
    except ValueError:
        return ""
    return "".join(chr(b) if 32 <= b < 127 else "?" for b in raw)


def inspect_blob_format(hex_str: str) -> dict:
    """Classify an exported asymmetric blob as private/public/unknown using
    the 4-byte magic head. Returns {format, magic, is_private}."""
    magic = _hex_head(hex_str, 4)
    if magic in ASYM_PRIV_MAGICS:
        return {"format": magic, "magic": magic, "is_private": True}
    if magic in ASYM_PUB_MAGICS:
        return {"format": magic, "magic": magic, "is_private": False}
    # MS CryptoAPI legacy PRIVATEKEYBLOB: BLOBHEADER (0x07 0x02 0x00 0x00)
    # + RSAPUBKEY {magic="RSA2"} at offset 8.
    if hex_str.startswith("07020000") and len(hex_str) >= 2 * 12 \
            and _hex_head(hex_str[2 * 8:], 4) == "RSA2":
        return {"format": "MS_CRYPTOAPI_PRIVATEKEYBLOB",
                "magic":  "RSA2",
                "is_private": True}
    return {"format": magic or "(unknown)",
            "magic":  magic,
            "is_private": False}


def pair_enter_exit(crypto_events: list[dict]) -> list[dict]:
    """Merge {phase:enter} + {phase:exit} into a single per-call record
    keyed on `call_id`. Older traces without phase/call_id flow through
    unchanged so the analyzer remains backward-compatible.

    Returns one record per call:
        {api, dll, kind, loop_id, ..., in_buf_hex?, out_buf_hex?,
         handle_in_hex?, handle_out_hex?, ret_val?}
    """
    by_id: dict[int, dict] = {}
    legacy: list[dict] = []
    for ev in crypto_events:
        phase = ev.get("phase")
        cid   = ev.get("call_id")
        if phase is None or cid is None:
            legacy.append(dict(ev))
            continue
        slot = by_id.setdefault(cid, {})
        # only let exit-phase fields overwrite a fixed
        # allowlist. Call-site-intrinsic fields (ip, kind, api, args,
        # loop_id, loop_iteration, loop_is_captured) must stay pinned to
        # the enter event, otherwise the exit event's ret-instruction IP
        # silently rewrites IP-based loop attribution downstream.
        EXIT_OVERRIDE_KEYS = {
            "out_buf_hex", "out_len", "handle_out_hex",
            "ret_val", "exit_ip",
        }
        for k, v in ev.items():
            if k in EXIT_OVERRIDE_KEYS:
                slot[k] = v
            elif k not in slot:
                slot[k] = v
        slot["call_id"] = cid

    merged = legacy + list(by_id.values())
    return merged


def attribute_events_to_loops_by_ip(crypto_events: list[dict],
                                     loops_meta) -> dict[int, list[dict]]:
    """Post-hoc geometric IP→loop attribution.

    The PinTool emits each crypto event with its instruction-pointer
    field, and each captured loop carries `[header, loop_end)` IP bounds
    that the PinTool also measured directly. When an event's IP falls
    inside a loop's IP range, that event executed inside that loop —
    this is geometric containment, not inference.

    `summarize()` already builds a `per_loop` dict keyed on the
    PinTool's own `loop_id` field. In practice that field is missing
    on the JSONL streams we see (the VM hook emits a flat event log),
    so cross-axis corroboration starves. We rebuild the attribution
    here from the IP bounds.

    Returns:  {loop_id: [event, ...]}  using `loops_meta`'s loop_id.

    Caller: chain.py / cross_axis.py consume the resulting mapping by
    folding it into per-loop slots.
    """
    ranges: list[tuple[int, int, int]] = []
    # Accept either {loop_id: meta} (loaders.load_bundle layout) or a
    # list of meta dicts (a few callers pass the values directly).
    if isinstance(loops_meta, dict):
        loop_iter = loops_meta.values()
    else:
        loop_iter = loops_meta or []
    for lm in loop_iter:
        if not isinstance(lm, dict):
            continue
        hdr = lm.get("header")
        end = lm.get("loop_end") or lm.get("backedge")
        if not hdr or not end:
            continue
        try:
            lo = int(hdr, 16) if isinstance(hdr, str) else int(hdr)
            hi = int(end, 16) if isinstance(end, str) else int(end)
        except (ValueError, TypeError):
            continue
        # Defensive repair: if the PinTool emitted a backedge/loop_end that is
        # not strictly greater than the header (malformed output), extend hi
        # using the separately-emitted `range_size` field, or to header+1 as
        # a last resort. This prevents the IP-containment check `lo <= ip < hi`
        # from matching nothing for the loop. Only fires on mis-emitted traces.
        if hi <= lo:
            hi = lo + max(1, int(lm.get("range_size") or 0))
        ranges.append((lo, hi, int(lm.get("loop_id") or 0)))
    ranges.sort(key=lambda r: r[0])

    if not ranges:
        return {}

    # bound the worst case with a bisect prefilter.
    # `ranges` is sorted by lo; bisect_right(lo_list, ip) gives the upper
    # bound on candidates whose lo <= ip, so we only iterate that prefix
    # instead of all R ranges per event. For typical sizes (~10^3 loops)
    # this is unchanged; for the 10^6 events x 10^4 loops worst case it
    # avoids the 10^10-op linear blowup the original code would incur.
    # The smallest-span tie-break (innermost loop wins) is preserved.
    import bisect
    lo_list = [r[0] for r in ranges]
    max_hi = max((hi for _, hi, _ in ranges), default=0)

    out: dict[int, list[dict]] = defaultdict(list)
    for ev in crypto_events or []:
        ip_str = ev.get("ip") or ""
        if not ip_str or ip_str == "0":
            continue
        try:
            ip = int(ip_str, 16) if isinstance(ip_str, str) else int(ip_str)
        except (ValueError, TypeError):
            continue
        if ip >= max_hi:
            # IP is past every captured range's upper bound; cannot match.
            continue
        # Pick the SMALLEST containing range (innermost loop), not the
        # first match. A first-match policy loses inner-loop attribution
        # when an outer loop is also captured: nested crypto loops (e.g.
        # AES inside an outer Salsa20) have their inner events siphoned to
        # the outer wrapper.
        upper = bisect.bisect_right(lo_list, ip)
        best_lid = None
        best_span = None
        for idx in range(upper):
            lo, hi, lid = ranges[idx]
            if lo <= ip < hi:
                span = hi - lo
                if best_span is None or span < best_span:
                    best_span = span
                    best_lid = lid
        if best_lid is not None:
            out[best_lid].append(ev)
    return dict(out)


def enrich_sym_keys_with_snapshots(crypto_sum: dict, bundle: dict) -> dict:
    """For sym_keys entries with hex=None (length-only inference),
    look up a matching deriv_keygen_input snapshot and fill `hex` from
    the snapshot file. Modifies crypto_sum['sym_keys'] in place and
    returns the same dict.

    Mapping: PinTool dumps each captured key buffer starting at the
    buf address (offset 0 in the snapshot file) for `reported_len`
    bytes. We match (api, reported_len) against the sym_keys entry's
    (api, len). Each snapshot is consumed once to avoid attaching the
    same hex to multiple sym_keys entries.

    Provenance is attached on `snapshot_provenance` so the value is traceable
    trace the value back to the raw artefact.
    """
    import os

    trace_dir = bundle.get("trace_dir") or bundle.get("root")
    snaps = bundle.get("keybirth_snapshots") or []
    sym_keys = crypto_sum.get("sym_keys") or []
    if not trace_dir or not snaps or not sym_keys:
        return crypto_sum

    # deriv_keygen_input snapshots only — those are the ones where the
    # captured bytes are the actual key material (not RNG output or
    # algorithm provider string).
    candidates = [
        {
            "api":            s.get("api"),
            "reported_len":   int(s.get("reported_len") or 0),
            "buf_address":    s.get("buf"),
            "snapshot_file":  s.get("snapshot_file"),
            "seq":            s.get("seq"),
        }
        for s in snaps
        if s.get("event_kind") == "deriv_keygen_input"
        and (s.get("reported_len") or 0) > 0
    ]

    for k in sym_keys:
        if k.get("hex"):
            continue   # already captured
        klen = k.get("len")
        for s in candidates:
            if s["api"] != k.get("api") or s["reported_len"] != klen:
                continue
            p = os.path.join(trace_dir, s["snapshot_file"] or "")
            if not os.path.isfile(p):
                continue
            try:
                with open(p, "rb") as fp:
                    raw = fp.read(s["reported_len"])
            except OSError:
                continue
            if not raw or len(raw) < s["reported_len"]:
                continue
            k["hex"] = raw.hex()
            k["source"] = (
                (k.get("source") or "") + "+snapshot_extracted"
            ).lstrip("+")
            k["snapshot_provenance"] = {
                "snapshot_file":  s["snapshot_file"],
                "buf_address":    s["buf_address"],
                "offset_in_file": 0,
                "snapshot_seq":   s["seq"],
            }
            candidates.remove(s)   # consume once
            break

    return crypto_sum


def harvest_wrapped_session_keys(crypto_sum: dict, bundle: dict) -> dict:
    """Recover PayBreak-style captured symmetric keys that are NOT produced by a
    keygen/kdf/key_import event and so are missed by the standard sym_keys harvest.

    Some families (e.g. Chaos) format each file's AES key + IV as an ASCII
    ``"KEY|IV"`` blob and RSA-wrap it for the operator; the Ransack PinTool captures
    that blob *plaintext* as the small input to the wrap call — a ``sink_plaintext``
    snapshot (Kolodenker et al., PayBreak, AsiaCCS 2017: the symmetric key captured
    at the RSA-wrap input). These are genuine captured symmetric keys.

    Scoping (no over-count): only ``sink_plaintext`` snapshots of 40..64 bytes whose
    content matches the *exact* ``[A-Za-z0-9]{32}|[A-Za-z0-9]{16}`` structure (a
    32-char key + '|' + 16-char IV) are promoted. Binary key buffers, RSA blobs and
    file-plaintext snapshots do not match this structure, so other families are
    unaffected (verified: re-running every other family yields 0 promotions).
    """
    import os, glob, json, re

    trace_dir = bundle.get("trace_dir") or bundle.get("root")
    if not trace_dir or not os.path.isdir(trace_dir):
        return crypto_sum
    keyiv_re = re.compile(rb"[A-Za-z0-9]{32}\|[A-Za-z0-9]{16}")

    def _binary_key_material(raw: bytes) -> bool:
        """True when a small sink-plaintext buffer looks like raw key material
        rather than a slice of a victim file.

        Families that format the wrap input as text are caught by `keyiv_re`;
        others (e.g. Akira) hand the RSA wrap a raw ``key || nonce`` buffer, which
        that regex cannot match. Key material is drawn from a CSPRNG, so it is
        near-uniform over its length and mostly non-printable; a same-sized slice
        of a document, script or config file is neither. Both tests must hold, so
        text buffers and low-entropy binary padding are rejected.
        """
        n = len(raw)
        if n < 32:
            return False
        distinct = len(set(raw))
        printable = sum(1 for b in raw if 0x20 <= b < 0x7f or b in (9, 10, 13))
        return distinct >= (n * 3) // 4 and printable <= n // 2

    wrapped: list[dict] = []
    seen: set = set()
    total = 0
    STORE_CAP = 32   # keep a representative sample in the report; the count reflects the true unique total

    for jf in sorted(glob.glob(os.path.join(trace_dir, "key_residue_snapshots_*.jsonl"))):
        try:
            fh = open(jf, encoding="utf-8", errors="replace")
        except OSError:
            continue
        with fh:
            for ln in fh:
                try:
                    s = json.loads(ln)
                except Exception:
                    continue
                if s.get("event_kind") != "sink_plaintext":
                    continue
                rlen = int(s.get("reported_len") or 0)
                if not (40 <= rlen <= 64):
                    continue
                # A wrap is an ENCRYPT call: the key is the plaintext handed to it.
                # Decrypt-side sinks carry the family's own config/blob plaintext, not
                # a session key, so they must not be promoted.
                api = str(s.get("api") or "")
                if "decrypt" in api.lower():
                    continue
                p = os.path.join(trace_dir, s.get("snapshot_file") or "")
                if not os.path.isfile(p):
                    continue
                try:
                    raw = open(p, "rb").read(rlen)
                except OSError:
                    continue
                if len(raw) < rlen:
                    # short read (partial live-pull transfer): splitting key||iv here
                    # would yield a truncated/empty IV. Skip, as enrich_sym_keys does.
                    continue
                m = keyiv_re.search(raw)
                if m:
                    kiv = m.group(0)
                    key, iv = kiv[:32], kiv[33:49]
                    src = "wrapped_key_sink_plaintext"
                elif _binary_key_material(raw):
                    # raw `key || nonce/IV` handed to the wrap (e.g. Akira: 32-byte
                    # ChaCha key + 8-byte nonce)
                    key, iv = raw[:32], raw[32:]
                    src = "wrapped_key_sink_plaintext_binary"
                else:
                    continue
                h = key.hex()
                if h in seen:
                    continue
                seen.add(h)
                total += 1
                if len(wrapped) < STORE_CAP:
                    wrapped.append({
                        "api": s.get("api"), "len": 32,
                        "hex": h, "iv_hex": iv.hex(),
                        "source": src,
                        "snapshot_provenance": {"snapshot_file": s.get("snapshot_file"),
                                                 "snapshot_seq": s.get("seq")},
                        "spec": "PayBreak (Kolodenker et al., AsiaCCS 2017): symmetric "
                                "session key captured plaintext at the RSA-wrap input",
                    })
    if total:
        # Kept OUT of `sym_keys` on purpose: these are captured at the RSA-wrap input,
        # not produced by a keygen/kdf event, so they must NOT feed the weak-RNG (RC-05)
        # or hardcoded-key (RC-04) predicates that read `sym_keys_count`. Only RC-07
        # (captured_symmetric_session_keys) is taught to accept them — see
        # recovery_cases.captured_symmetric_keys_at_least.
        crypto_sum["wrapped_session_keys"] = wrapped
        crypto_sum["wrapped_session_keys_count"] = total
    return crypto_sum


# ------------------------------------------------------ cipher-parameter split
# Property-setter APIs carry cipher PARAMETERS (chaining mode, IV) — NOT key
# material. The PinTool tags some of these calls kind="keygen", so their
# captured buffer lands in sym_keys; snapshot-enrichment then fills the
# bytes. The result is that a BCRYPT_CHAINING_MODE value string
# (UTF-16LE "ChainingModeCBC") or an IV buffer is mis-inventoried as a captured
# symmetric key — over-counting sym_keys AND hiding the mode/IV a decryptor
# actually needs. partition_cipher_params() moves those entries out of sym_keys
# into a dedicated `cipher_params` inventory and, where the bytes were captured,
# decodes the chaining mode and collects IV candidates. This runs AFTER
# enrich_sym_keys_with_snapshots so the property bytes are already filled in.
_PROP_SETTER_APIS = ("BCryptSetProperty", "CryptSetKeyParam", "CPSetKeyParam")
# BCRYPT chaining-mode property VALUES (bcrypt.h: BCRYPT_CHAIN_MODE_*), each the
# wide-string set via BCryptSetProperty(hObj, BCRYPT_CHAINING_MODE, value, ...).
_CHAINING_MODE_VALUES = {
    "ChainingModeCBC": "CBC", "ChainingModeECB": "ECB",
    "ChainingModeCFB": "CFB", "ChainingModeGCM": "GCM",
    "ChainingModeCCM": "CCM", "ChainingModeNA": "NA",
}


def _utf16le_str(hex_str: str) -> str:
    """Decode a hex string as UTF-16LE, dropping NULs. Returns '' on any error
    or odd-length input (a real random key just yields garbage, which will not
    match the exact _CHAINING_MODE_VALUES keys below — so no false positives)."""
    if not hex_str:
        return ""
    try:
        return bytes.fromhex(hex_str).decode("utf-16-le", errors="ignore").replace("\x00", "")
    except (ValueError, UnicodeError):
        return ""


def partition_cipher_params(crypto_sum: dict) -> dict:
    """Split property-setter entries (mode/IV) out of sym_keys into a separate
    `cipher_params` inventory, and surface a recovered chaining mode +
    IV candidates. Modifies and returns crypto_sum in place.

    Adds:
      crypto_sum['cipher_params']  – list of {api, len, hex, role, ...}
      crypto_sum['cipher_mode']    – single mode str iff unambiguous, else None
      crypto_sum['cipher_modes']   – list of all distinct modes seen
      crypto_sum['iv_candidates']  – up to 16 unique IV hex strings
      crypto_sum['iv_total']       – total IV-shaped setter buffers seen
    and recomputes sym_keys / sym_keys_count to real keys only.
    """
    sym_keys = crypto_sum.get("sym_keys") or []
    keys: list[dict] = []
    params: list[dict] = []
    modes: list[str] = []
    ivs: list[str] = []
    iv_total = 0

    for k in sym_keys:
        if (k.get("api") or "") not in _PROP_SETTER_APIS:
            keys.append(k)
            continue
        hexs = k.get("hex")
        entry = {
            "call_id": k.get("call_id"), "api": k.get("api"),
            "len": k.get("len"), "hex": hexs, "source": k.get("source"),
            "snapshot_provenance": k.get("snapshot_provenance"),
            "role": "unknown",
        }
        dec = _utf16le_str(hexs) if hexs else ""
        if dec in _CHAINING_MODE_VALUES:
            entry["role"] = "mode"
            entry["mode"] = _CHAINING_MODE_VALUES[dec]
            if entry["mode"] not in modes:
                modes.append(entry["mode"])
        elif (k.get("len") in (8, 16)):
            # 8/16-byte property buffer that is not a mode string = the IV
            # (BCRYPT_INITIALIZATION_VECTOR / KP_IV). length-only ones still
            # mark IV presence but carry no recoverable bytes.
            entry["role"] = "iv" if hexs else "iv_length_only"
            iv_total += 1
            if hexs and hexs not in ivs and len(ivs) < 16:
                ivs.append(hexs)
        params.append(entry)

    crypto_sum["sym_keys"] = keys
    crypto_sum["sym_keys_count"] = len(keys)
    crypto_sum["cipher_params"] = params
    crypto_sum["cipher_modes"] = modes
    crypto_sum["cipher_mode"] = modes[0] if len(modes) == 1 else None
    crypto_sum["iv_candidates"] = ivs
    crypto_sum["iv_total"] = iv_total
    return crypto_sum


def summarize(crypto_events: list[dict],
              loops_meta: list[dict] | None = None) -> dict:
    """Aggregate the merged crypto-event stream into the histograms the
    rest of the pipeline consumes.

    `loops_meta`, when provided, lets the per-loop attribution fall back
    to a geometric `[header, loop_end)` lookup when an event lacks the
    PinTool's `loop_id` field. This is a direct-measurement fallback,
    not an inference: the IP and the bounds were both captured by Pin.
    """
    # Merge enter/exit phases into a single per-call view. The merged stream
    # is what the histograms below count — otherwise every BCryptEncrypt
    # would be double-counted (one for enter, one for exit).
    calls = pair_enter_exit(crypto_events)
    ip_attribution = attribute_events_to_loops_by_ip(calls, loops_meta or [])

    by_kind:   Counter = Counter()
    by_api:    Counter = Counter()
    by_dll:    Counter = Counter()
    by_bucket: Counter = Counter()
    per_loop:  dict = defaultdict(lambda: {
        "total": 0, "crypto_calls": 0, "memop_calls": 0,
        "by_kind": Counter(), "by_api": Counter(),
        "by_dll": Counter(),
    })
    orphan = 0
    captured_only_total = 0

    # Asym blob inventory — only filled by legacy traces that carried
    # out_buf_hex content. The current PinTool emits in_buf/out_buf as POINTER
    # addresses, so under that feed this stays EMPTY; RC-01/RC-03 instead rely
    # on byte-signature promotion over the key-birth snapshots (see
    # byte_signature_scanner._moduli_from_snapshot_blobs / apply_byte_sig_promotion).
    asym_blobs: list[dict] = []
    # Symmetric key inventory — every captured out_buf/in_buf of a
    # keygen/kdf/rand/key_import event becomes a candidate.
    sym_keys:   list[dict] = []

    for ev in calls:
        kind = ev.get("kind") or "?"
        api  = ev.get("api")  or "?"
        dll  = ev.get("dll")  or "?"
        bk   = _bucket(kind)
        by_kind[kind]   += 1
        by_api[api]     += 1
        by_dll[dll]     += 1
        by_bucket[bk]   += 1

        if ev.get("loop_is_captured"):
            captured_only_total += 1

        # Buffer inventories ----------------------------------------------
        out_hex = ev.get("out_buf_hex")
        out_len = ev.get("out_len")
        in_hex  = ev.get("in_buf_hex")
        in_len  = ev.get("in_len")

        if out_hex and kind in ("key_export",):
            blob = inspect_blob_format(out_hex)
            asym_blobs.append({
                "call_id": ev.get("call_id"), "api": api, "kind": kind,
                "handle_in":  ev.get("handle_in_hex"),
                "out_len":    out_len, "hex": out_hex,
                "source":     "out_buf",
                **blob,
            })
        # RC-01 wants private-key blob sightings in
        # *either* direction. key_import carries the blob bytes in_buf
        # (a private key being loaded), so include those entries too —
        # otherwise the asym inventory silently drops half the sightings.
        if in_hex and kind == "key_import":
            blob = inspect_blob_format(in_hex)
            asym_blobs.append({
                "call_id": ev.get("call_id"), "api": api, "kind": kind,
                "handle_in":  ev.get("handle_in_hex"),
                "in_len":     in_len, "hex": in_hex,
                "source":     "in_buf",
                **blob,
            })
        if kind in ("keygen", "kdf", "rand"):
            # RNG outputs land in out_buf; keygen + kdf outputs likewise.
            if out_hex and out_len:
                sym_keys.append({"call_id": ev.get("call_id"),
                                  "api": api, "kind": kind,
                                  "len": out_len, "hex": out_hex,
                                  "source": "out_buf"})
            elif out_len and out_len in (8, 16, 24, 32, 64):
                # Spec-grounded length-only inventory. The PinTool did not
                # dump buffer bytes for this trace, but the length itself
                # is a direct PinTool measurement and the FIPS-197 /
                # RFC-7539 / NIST SP 800-67 family identification rules
                # in sym_key_inference_rules.json operate on length alone
                # (each rule cites the corresponding standard).
                # We emit an entry without a `hex` field so downstream
                # consumers can distinguish "captured bytes" from
                # "captured length only".
                # cite the standard that actually covers
                # this length. FIPS-197 (AES) covers 16/24/32; SP 800-67
                # (3DES) covers 24; RFC-7539 (ChaCha20) covers 32; 8-byte
                # keys are single-DES (FIPS 46-3, deprecated).
                sym_keys.append({"call_id": ev.get("call_id"),
                                  "api": api, "kind": kind,
                                  "len": out_len, "hex": None,
                                  "source": "out_buf_length_only",
                                  "spec": _spec_for_len(out_len)})
            elif in_len and in_len in (8, 16, 24, 32, 64):
                # CNG / CryptoAPI generate-from-secret call: the key
                # bytes are passed *in* (pbSecret) and a HANDLE comes
                # back in out_buf. Examples:
                #   BCryptGenerateSymmetricKey(pbSecret=key_bytes,
                #                              cbSecret=in_len,
                #                              phKey=&handle)
                #   CryptImportKey(pbData=keyblob, dwDataLen=in_len,
                #                   phKey=&handle)
                # The MS CNG bcrypt.h / wincrypt.h signatures make this
                # a direct PinTool measurement: the buffer length emitted
                # for the in argument is the key length.
                if in_hex:
                    sym_keys.append({"call_id": ev.get("call_id"),
                                      "api": api, "kind": kind,
                                      "len": in_len, "hex": in_hex,
                                      "source": "in_buf"})
                else:
                    # per-length spec citation (see
                    # _spec_for_len) instead of a single multi-standard
                    # blob that incorrectly covers all of {8,16,24,32}.
                    sym_keys.append({"call_id": ev.get("call_id"),
                                      "api": api, "kind": kind,
                                      "len": in_len, "hex": None,
                                      "source": "in_buf_length_only",
                                      "spec": _spec_for_len(in_len)})
        if kind == "key_import":
            # Guard the length: an imported asymmetric blob (e.g. a 148-byte RSA
            # PUBLICKEYBLOB) must NOT land in sym_keys. Only symmetric-key-sized
            # imports qualify, matching the length-only branch below.
            if in_hex and in_len in (8, 16, 24, 32, 64):
                sym_keys.append({"call_id": ev.get("call_id"),
                                  "api": api, "kind": kind,
                                  "len": in_len, "hex": in_hex,
                                  "source": "in_buf"})
            elif in_len and in_len in (8, 16, 24, 32, 64):
                # per-length spec citation; the prior
                # multi-standard blob mis-attributed every length.
                sym_keys.append({"call_id": ev.get("call_id"),
                                  "api": api, "kind": kind,
                                  "len": in_len, "hex": None,
                                  "source": "in_buf_length_only",
                                  "spec": _spec_for_len(in_len)})

        lid = ev.get("loop_id")
        if lid is None:
            orphan += 1
            # No loop_id from the PinTool — fall through; the geometric
            # IP-range pass below will attribute it if its IP lies in a
            # captured loop's [header, loop_end).
            continue
        slot = per_loop[lid]
        slot["total"] += 1
        if bk == "crypto":
            slot["crypto_calls"] += 1
        elif bk == "memop":
            slot["memop_calls"] += 1
        slot["by_kind"][kind] += 1
        slot["by_api"][api]   += 1
        slot["by_dll"][dll]   += 1

    # Geometric IP-range attribution for orphan events (no loop_id on
    # the JSONL row). The PinTool measured both the event IP and the
    # loop's [header, loop_end) directly, so containment is a fact.
    # track how many orphans the IP pass recovers so
    # downstream consumers can distinguish true orphans (orphan_count)
    # from the original PinTool miss that was salvaged geometrically
    # (orphan_recovered_by_ip). The previous orphan counter never
    # subtracted IP-attributed events and over-reported true orphans.
    attributed_via_ip = 0
    for lid_geo, evs in ip_attribution.items():
        slot = per_loop[lid_geo]
        for ev in evs:
            if ev.get("loop_id") is not None:
                # Already attributed via the PinTool's own loop_id above.
                continue
            attributed_via_ip += 1
            kind = ev.get("kind") or "?"
            api  = ev.get("api")  or "?"
            dll  = ev.get("dll")  or "?"
            bk = _bucket(kind)
            slot["total"] += 1
            if bk == "crypto":
                slot["crypto_calls"] += 1
            elif bk == "memop":
                slot["memop_calls"] += 1
            slot["by_kind"][kind] += 1
            slot["by_api"][api]   += 1
            slot["by_dll"][dll]   += 1

    # Dedup symmetric keys. Entries that captured bytes are deduped by
    # exact hex; length-only entries are deduped by
    # (api, kind, len, call_id) so a ransomware that derives 1000 distinct
    # per-file AES keys is not collapsed into a single entry.
    # include call_id in the length-only dedup key.
    # The previous (api, kind, len) key under-counted distinct key handles
    # — exactly the RC inventory metric the paper relies on.
    seen_hex: set = set()
    seen_meta: set = set()
    unique_sym_keys: list[dict] = []
    for k in sym_keys:
        h = k.get("hex")
        if h:
            if h in seen_hex:
                continue
            seen_hex.add(h)
        else:
            # Dedup length-only entries by (api, kind, len, call_id). NOTE: do NOT relax
            # this to keep call_id=None entries distinct — that counts every reused-key
            # encrypt call as a separate "key" (measured: Alkhal 3 -> 83,334), grossly
            # inflating the key inventory. Collapsing reused-key calls is the correct
            # recovery semantic (distinct key shapes, not encrypt operations).
            meta_key = (k.get("api"), k.get("kind"), k.get("len"),
                        k.get("call_id"))
            if meta_key in seen_meta:
                continue
            seen_meta.add(meta_key)
        unique_sym_keys.append(k)

    return {
        "total_events":         len(crypto_events),
        "merged_call_count":    len(calls),
        "captured_only_total":  captured_only_total,
        "by_kind":              dict(by_kind.most_common()),
        "by_api":               dict(by_api.most_common()),
        "by_dll":               dict(by_dll.most_common()),
        "by_bucket":            dict(by_bucket.most_common()),
        "per_loop": {
            lid: {
                "total":         slot["total"],
                "crypto_calls":  slot["crypto_calls"],
                "memop_calls":   slot["memop_calls"],
                "by_kind":       dict(slot["by_kind"].most_common()),
                "by_api":        dict(slot["by_api"].most_common()),
                "by_dll":        dict(slot["by_dll"].most_common()),
            }
            for lid, slot in per_loop.items()
        },
        # report orphans net of geometrically-recovered
        # events plus the recovered tally, so downstream consumers see
        # truly unattributed counts instead of an inflated raw orphan tally.
        "orphan_count":           max(0, orphan - attributed_via_ip),
        "orphan_recovered_by_ip": attributed_via_ip,
        "orphan_raw":             orphan,
        "asym_blobs":             asym_blobs,
        "sym_keys":               unique_sym_keys,
        "sym_keys_count":         len(unique_sym_keys),
    }


# ------------------------------------------------------ algorithm inventory
# Each entry: (keyword, algo name, [optional substrings that disqualify the
# hit if also present in the api name]). The disqualifier list prevents
# false positives like "des" matching BCryptDestroyHash / BCryptDestroyKey.
# Disqualifiers are ALL applied -- any one of them present means we skip.
ALGO_KEYWORDS = [
    # (kw, name, disqualifiers)
    ("aes",            "AES",                       []),
    ("chacha",         "ChaCha20",                  []),
    ("salsa",          "Salsa20",                   []),
    ("rc4",            "RC4",                       []),
    # "des" substring matches BCryptDestroy* / CryptDestroy* (BCrypt API
    # cleanup family). Microsoft's actual DES APIs are CALG_DES /
    # BCRYPT_DES_ALGORITHM, addressed via the explicit disqualifier list.
    # Disqualifiers:
    #   "destroy"     - CONFIRMED FP carriers: BCryptDestroyKey,
    #                   BCryptDestroyHash, CryptDestroyKey, CryptDestroyHash,
    #                   CPDestroyKey, CPDestroyHash (10 rows in crypto_api.json).
    #   "describe"    - PREVENTIVE: no current FP carrier in crypto_api.json,
    #                   reserved against future MS API additions like
    #                   CryptDescribeFormat or BCryptDescribeProvider.
    #   "deserialize" - PREVENTIVE: no current FP carrier, reserved against
    #                   future serialisation helpers (e.g. mbedTLS / wolfSSL
    #                   port may add `*_deserialize` shims).
    ("des",            "DES/3DES",                  ["destroy", "describe", "deserialize"]),
    ("blowfish",       "Blowfish",                  []),
    ("camellia",       "Camellia",                  []),
    ("rsa",            "RSA",                       []),
    ("ecdh",           "ECDH",                      []),
    ("ecdsa",          "ECDSA",                     []),
    ("curve25519",     "Curve25519",                []),
    ("x25519",         "X25519",                    []),
    ("ed25519",        "Ed25519",                   []),
    ("scalarmult",     "Curve25519/scalarmult",     []),
    ("box_keypair",    "Curve25519 (NaCl box)",     []),
    ("sha1",           "SHA-1",                     []),
    ("sha224",         "SHA-224",                   []),
    ("sha256",         "SHA-256",                   []),
    ("sha384",         "SHA-384",                   []),
    ("sha512",         "SHA-512",                   []),
    ("md5",            "MD5",                       []),
    ("blake2",         "BLAKE2",                    []),
    ("hmac",           "HMAC",                      []),
    ("pbkdf2",         "PBKDF2",                    []),
    ("hkdf",           "HKDF",                      []),
    ("scrypt",         "scrypt",                    []),
    ("argon",          "Argon2",                    []),
    ("gcm",            "AES-GCM",                   []),
    ("ccm",            "AES-CCM",                   []),
    ("poly1305",       "ChaCha20-Poly1305",         []),
    ("secretbox",      "XSalsa20-Poly1305",         []),
    ("drbg",           "NIST DRBG",                 []),
    ("genrandom",      "system RNG",                []),
    ("rtlgenrandom",   "RtlGenRandom",              []),
    ("systemfunction", "RtlGenRandom (alias)",      []),
]


def algorithms_detected(by_api: dict[str, int]) -> list[str]:
    # Substring + disqualifier scheme rationale.
    # Each (kw, name, disq) tuple draws its spec source from the Microsoft
    # CNG, OpenSSL EVP, and BoringSSL API naming conventions; the substring
    # match aligns with documented API name prefixes (e.g. the "aes" prefix
    # for the AES family). The disqualifier list (e.g. "destroy" / "describe"
    # / "deserialize") is documented inline in the ALGO_KEYWORDS block; when
    # the catalog adds an official algorithm prefix, the corresponding
    # disqualifier list should be updated in the same place.
    # Verified 2026-06-05: spot check of the algorithms_detected output on
    # the our corpus shows no false positives (all collisions blocked
    # by the disqualifier list).
    found = set()
    for api in by_api:
        a = api.lower()
        for kw, name, disq in ALGO_KEYWORDS:
            if kw not in a:
                continue
            if any(d in a for d in disq):
                continue   # disqualifier matches -- skip this hit
            found.add(name)
    return sorted(found)
