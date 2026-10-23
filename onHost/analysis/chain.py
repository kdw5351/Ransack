"""Key derivation chain graph (paper §III).

Reconstructs the parent → child key derivation graph from the PinTool's
`src` / `deriv` / `sink` event stream and computes the graph-level
statistics that several RC primitives consume (RC-04, RC-05).

Event shapes the PinTool emits (one record per JSONL line):

  ``src``     {tag, api, kind=rand, buf, len, ip, tid}
              RNG source.  Tag is materialised here.

  ``deriv``   {parent, child, api, kind, in_buf, in_len, out_buf,
               out_len, handle, ip, tid}
              A keygen / kdf / hash / key_import / key_export operation
              that turns one key tag into another.  Tag ``0`` on either
              side means "no upstream material recorded"; the child is
              new, the parent is treated as an embedded root.

  ``sink``    {tag, api, kind=sym_enc|asym_enc, in_buf, in_len, out_buf,
               out_len, handle, ip, tid}
              The tagged key was consumed by an encryption call. Marks
              the chain terminus for that tag.

Two folds the paper §III explicitly mandates:

  * Repetitive ``(api, kind, ip)`` tuples on the same ``(parent, child)``
    edge collapse into a single edge with a ``count`` field and the
    first captured key bytes preserved.  This keeps a sample that
    re-emits the same BCryptFinishHash blob on every loop iteration
    from inflating the graph by 10^6 entries.

  * Tags that appear as a ``parent`` but never as a ``child`` and were
    never declared in a ``src`` event are *embedded roots*: hardcoded
    or .rdata-loaded key material that has no observable RNG ancestor.
    They are tracked separately because RC-04 keys on exactly that
    population.

Graph stats exposed for downstream consumers:

  ``node_count``                  unique tags seen
  ``edge_count``                  unique (parent, child, api, kind, ip)
  ``source_count``                tags born in a ``src`` event
  ``embedded_root_count``         parent-only tags with no ``src``
  ``sink_count``                  tags that terminated in a sink event
  ``sinks_with_rng_ancestor``     sinks reachable from a ``src`` tag
  ``sinks_without_rng_ancestor``  sinks reachable only from an
                                  embedded root (i.e. hardcoded key)
  ``hardcoded_key_ratio``         sinks_without_rng_ancestor / sink_count
  ``rng_to_keygen_paths``         top-level list (not in ``stats``) of
                                  (rng_tag, keygen_tag) pairs where the keygen
                                  tag is reachable from the rng tag — RC-05
                                  evidence; ``stats`` carries the count as
                                  ``rng_to_keygen_path_count``
  ``max_chain_depth``             longest path length in the DAG
"""
from __future__ import annotations



# Event kinds that count as a "key birth" (something that produces a
# fresh tag downstream). Any kind not in this set falls through to the
# generic deriv-node bookkeeping.
KEYGEN_KINDS  = {"keygen", "kdf"}  # key_import excluded: an externally-supplied imported key is not RNG-generated, so it must not count as an RC-05 keygen node (matches _KEYGEN_APIS intent below)
RNG_KINDS     = {"rand"}
SINK_KINDS    = {"sym_enc", "asym_enc"}


# Spec-grounded handle-based provenance map: MS Learn documents these
# API chains as the standard way CNG/CryptoAPI key material flows from
# entropy source -> key handle -> encryption sink.  We use API ↔ kind
# pairs to type-check each step, and the runtime `handle` field
# (PinTool-emitted, not inferred) to bind them.  No time-window
# inference is performed; equality of the handle byte string is the
# fact we rely on.
#
# Source: Microsoft Learn — "Cryptography Next Generation (CNG) Reference"
#   https://learn.microsoft.com/en-us/windows/win32/seccng/cng-reference
# and "CryptoAPI / Wincrypt.h reference"
#   https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/
HANDLE_PRODUCER_APIS = {
    # CNG: BCryptOpenAlgorithmProvider returns an alg handle that
    # BCryptGenerateSymmetricKey then consumes (MS Learn).
    "BCryptOpenAlgorithmProvider",
    "BCryptGenerateSymmetricKey",
    "BCryptGenerateKeyPair",
    "BCryptFinalizeKeyPair",
    "BCryptImportKey",
    "BCryptImportKeyPair",
    "BCryptDuplicateKey",
    "BCryptDeriveKey",
    # CryptoAPI legacy chain
    "CryptAcquireContextW",
    "CryptAcquireContextA",
    "CryptGenKey",
    "CryptDeriveKey",
    "CryptImportKey",
    "CryptDuplicateKey",
    # Hash handles (kdf chain)
    "BCryptCreateHash",
    "CryptCreateHash",
}
HANDLE_CONSUMER_APIS = {
    "BCryptEncrypt", "BCryptDecrypt",
    "CryptEncrypt", "CryptDecrypt",
    "BCryptExportKey", "CryptExportKey",
    "BCryptHashData", "CryptHashData",
    "BCryptFinishHash", "CryptGetHashParam",
    "BCryptSignHash", "BCryptVerifySignature",
}


def _empty_node(tag: int) -> dict:
    return {
        "tag":             tag,
        "born_by":         None,           # (api, kind, ip) on first sight
        "parents":         set(),          # tags that derived to this
        "children":        set(),          # tags this derived into
        "is_src":          False,          # appeared in a `src` event
        "is_sink":         False,          # appeared in a `sink` event
        "is_embedded_root": False,         # parent-only, never src/child
        "sink_apis":       set(),          # which sinks consumed this
        "derived_via":     set(),          # (api, kind) tags seen as deriv source
        "first_bytes_hex": None,           # first non-empty key bytes captured
    }


def _ensure_node(nodes: dict, tag: int) -> dict:
    if tag not in nodes:
        nodes[tag] = _empty_node(tag)
    return nodes[tag]


def _maybe_record_bytes(node: dict, hex_str: str | None) -> None:
    """Stash the first non-empty hex we observe for this tag, so the
    later RC-04 "preserve key bytes" requirement is satisfied."""
    if node["first_bytes_hex"]:
        return
    if hex_str and isinstance(hex_str, str):
        node["first_bytes_hex"] = hex_str


def _edge_key(parent: int, child: int, api: str, kind: str, ip: str) -> tuple:
    return (parent, child, api or "", kind or "", ip or "")


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def _safe_int(x, default: int = 0) -> int:
    # tolerate non-numeric tag strings (e.g. '0x1234',
    # 'abc') from PinTool output instead of aborting build() with ValueError.
    try:
        if isinstance(x, str):
            s = x.strip()
            if not s:
                return default
            return int(s, 0)
        if x is None:
            return default
        return int(x)
    except (ValueError, TypeError):
        return default


def build(crypto_events: list[dict]) -> dict:
    """Walks the raw crypto event stream and returns the chain graph dict.
    No mutation of inputs."""
    nodes: dict[int, dict] = {}
    # edge dedup: {(parent, child, api, kind, ip): {parent, child, api, kind,
    #   ip, count, in_len, out_len}}
    edges: dict[tuple, dict] = {}

    for ev in crypto_events or []:
        kind_of_event = ev.get("ev")
        if kind_of_event not in ("src", "deriv", "sink"):
            continue

        api = ev.get("api", "") or ""
        ip  = ev.get("ip", "")  or ""
        op_kind = (ev.get("kind") or "").lower()

        if kind_of_event == "src":
            # _safe_int tolerates hex/garbage tag strings.
            tag = _safe_int(ev.get("tag", 0))
            if tag <= 0:
                continue
            n = _ensure_node(nodes, tag)
            n["is_src"] = True
            if n["born_by"] is None:
                n["born_by"] = (api, op_kind, ip)
            # `src` carries the raw RNG output bytes in `buf` (just the
            # address, not the contents); the actual bytes are in
            # sym_keys via crypto_summary. We don't have hex on src
            # events themselves, so skip.
            continue

        if kind_of_event == "deriv":
            # _safe_int tolerates hex/garbage tag strings.
            parent = _safe_int(ev.get("parent", 0))
            child  = _safe_int(ev.get("child",  0))
            if child <= 0:
                # No new tag was materialised — pure transitive op
                # (e.g. memcpy with parent=child=0). Nothing graph-shaped
                # to record.
                continue

            # Ensure nodes exist.
            cnode = _ensure_node(nodes, child)
            if cnode["born_by"] is None:
                cnode["born_by"] = (api, op_kind, ip)
            cnode["derived_via"].add((api, op_kind))
            _maybe_record_bytes(cnode, ev.get("out_buf_hex"))

            if parent > 0:
                pnode = _ensure_node(nodes, parent)
                pnode["children"].add(child)
                cnode["parents"].add(parent)
                _maybe_record_bytes(pnode, ev.get("in_buf_hex"))

            # Edge fold.
            key = _edge_key(parent, child, api, op_kind, ip)
            edge = edges.get(key)
            if edge is None:
                edge = {
                    "parent": parent, "child": child,
                    "api": api, "kind": op_kind, "ip": ip,
                    "count": 0,
                    "in_len_total":  0,
                    "out_len_total": 0,
                }
                edges[key] = edge
            edge["count"]          += 1
            edge["in_len_total"]   += _safe_int(ev.get("in_len"))
            edge["out_len_total"]  += _safe_int(ev.get("out_len"))
            continue

        if kind_of_event == "sink":
            # _safe_int tolerates hex/garbage tag strings.
            tag = _safe_int(ev.get("tag", 0))
            if tag <= 0:
                # Sink without a tracked tag — happens when crypto API
                # received a key whose handle was never registered (e.g.
                # the sample loaded the key via a non-hooked path). We
                # still record an "anonymous" embedded-root sink so the
                # RC-04 ratio counts it.
                # use a stable string sentinel instead of
                # -1, which can collide with a legit -1 tag emitted by the
                # PinTool (signed-32-bit conversion of 0xFFFFFFFF, invalid
                # handle marker, etc.) and conflate anon-sink accounting
                # with embedded-root accounting. Also drop the direct
                # is_embedded_root write — Pass 2 will classify it as such
                # naturally because it has no parents and no src declaration.
                anon = "__anon_sink__"
                an = _ensure_node(nodes, anon)
                an["is_sink"]          = True
                an["sink_apis"].add(api)
                continue
            n = _ensure_node(nodes, tag)
            n["is_sink"] = True
            n["sink_apis"].add(api)

    # Pass 1.5: handle-based provenance enrichment.
    #
    # MS Learn documents that a CNG/CryptoAPI key handle is produced by
    # exactly one of HANDLE_PRODUCER_APIS and then consumed by one or more
    # HANDLE_CONSUMER_APIS that share the SAME handle byte string. The
    # PinTool emits the runtime handle directly in each event, so we can
    # bind producer-tag and consumer-tag with handle equality (no time
    # window, no heuristic — handle bytes match or they don't).
    #
    # For a child tag whose deriv event lists parent=0 but whose
    # producing API is a HANDLE_PRODUCER_APIS member, we look up the most
    # recent earlier deriv that produced the same handle and use its
    # child tag as the implicit parent. A sink event whose tag has no
    # recorded producer can likewise be linked back to a key-generation
    # parent via the shared handle.
    #
    # This recovers the RNG -> keygen -> sink chain that the PinTool
    # records as a flat list (because it never wires the parent field).
    # It is NOT inference about provenance; the handle equality IS the
    # observable evidence.
    # key handle map on (tid, handle) instead of just
    # handle. CNG/CryptoAPI handle values live in per-process namespaces,
    # so the same handle integer in different processes/threads refers to
    # unrelated keys. Binding across thread boundaries would wrongly fuse
    # independent chains. If no tid is available on the event, fall back
    # to a single bucket (callers must document single-threaded traces).
    # Pass 1.5 + 1.6 are folded into ONE event-ordered loop so the sink-side
    # binding (formerly Pass 1.6) resolves each handle against the producer known
    # AS-OF the sink event, not the finalized last-write-wins map. Reading the
    # finalized map non-temporally let a recycled handle (BCryptDestroyKey + a
    # later BCryptGenerate* reusing the same handle value) rebind a hardcoded-key
    # sink to a later RNG keygen, flipping RC-04's hardcoded_key_ratio to 0 (a
    # false negative on a genuinely-recoverable imported-key sample).
    handle_to_producer_tag: dict[tuple, int] = {}
    for ev in (crypto_events or []):
        kind = ev.get("ev")
        if kind not in ("deriv", "sink"):
            continue
        handle = ev.get("handle") or ""
        # widen invalid-handle skip set to cover empty
        # string (PinTool extraction failure) and common sentinels (NULL
        # as 0x0/0x00, INVALID_HANDLE_VALUE as 0xffffffff). Without this,
        # all extraction-failure events bucket under '' and bind into a
        # single bogus producer chain, polluting the graph.
        if not handle or handle in ("0", "?", "0x0", "0x00", "0xffffffff"):
            continue
        api = ev.get("api") or ""
        # scope handle key by tid for per-thread HANDLE-namespace correctness
        # (see Pass 1.5 header). NOTE: if the PinTool did not emit tid this
        # falls back to (None, handle) -- exact for the common single-crypto-
        # thread trace, but two threads that both omit tid and reuse the same
        # handle value could collapse (not observed in the corpus; crypto
        # events normally carry tid).
        tid = ev.get("tid")
        hkey = (tid, handle)

        if kind == "deriv":
            # _safe_int tolerates hex/garbage tag strings.
            child = _safe_int(ev.get("child", 0))
            parent = _safe_int(ev.get("parent", 0))
            if child <= 0:
                continue
            # Producer step: record this child as the handle's authoritative
            # producer tag (last-write-wins per handle, as CNG/CryptoAPI
            # re-use handles after BCryptDestroyKey + new BCryptGenerate*).
            if api in HANDLE_PRODUCER_APIS:
                handle_to_producer_tag[hkey] = child
            # Consumer step: if this consumer's parent tag is 0 but the
            # handle was previously produced, bind it.
            if api in HANDLE_CONSUMER_APIS and parent == 0:
                producer = handle_to_producer_tag.get(hkey)
                if producer and producer != child:
                    # Add the spec-grounded edge.
                    pnode = _ensure_node(nodes, producer)
                    cnode = nodes.get(child)
                    if cnode is not None and producer not in cnode["parents"]:
                        pnode["children"].add(child)
                        cnode["parents"].add(producer)
                        # when bind succeeds, promote the
                        # consumer's born_by to the producer's so the graph
                        # visualisation reports the child as 'born_by' the
                        # producer-side keygen rather than its consumer-side
                        # encrypt call (the previous behaviour was misleading).
                        if cnode is not None and pnode["born_by"] is not None:
                            cnode["born_by"] = pnode["born_by"]
            continue

        # kind == "sink": sink-side handle binding, bound to the producer known
        # AS-OF this sink event. If the tag's handle was produced by a keygen
        # already seen, treat the producer tag as a parent of the sink's tag (so
        # RC-04 / RC-05 ancestor walks succeed).
        # _safe_int tolerates hex/garbage tag strings.
        tag = _safe_int(ev.get("tag", 0))
        if tag <= 0:
            continue
        producer = handle_to_producer_tag.get(hkey)
        if not producer or producer == tag:
            continue
        snode = nodes.get(tag)
        if snode is None:
            continue
        # do not gate on 'no parents'. The previous
        # short-circuit made this binding weaker than intended — it could only
        # fill in a missing parent, never augment an existing (potentially
        # accidental) one. Always add the spec-grounded handle-binding
        # edge if it's not already present; the worst case is a node with
        # two parents, which the DAG fold handles correctly.
        if producer in snode["parents"]:
            continue
        pnode = _ensure_node(nodes, producer)
        pnode["children"].add(tag)
        snode["parents"].add(producer)

    # Pass 2: classify embedded roots (parent-only, never src, never as a
    # child).  Tags that *only* appeared as a `parent` in some deriv with
    # no `src` event of their own.
    # centralised classification — Pass 2 is now the
    # SOLE writer of is_embedded_root. The earlier direct write at the
    # anonymous-sink branch is removed; that node will be classified here
    # because it has no parents and no src declaration.
    for tag, n in nodes.items():
        if n["is_src"]:
            continue
        if n["parents"]:
            continue
        # No declared source AND no upstream parent => embedded root.
        n["is_embedded_root"] = True

    # Pass 3: ancestor reachability for RC-04 / RC-05.
    src_tags = {t for t, n in nodes.items() if n["is_src"]}
    embedded = {t for t, n in nodes.items() if n["is_embedded_root"]}
    sinks    = {t for t, n in nodes.items() if n["is_sink"]}

    # Reachability from source tags computed ONCE via a forward BFS over
    # `children`, instead of an O(sinks x nodes) per-sink ancestor sweep. A
    # pathological follow_memcpy fan-out (observed hanging analyze_trace for
    # hours on trace_Purgen_1) blows len(sinks)*len(nodes) into the billions;
    # this forward pass is O(nodes + edges) and yields the identical
    # classification, since a sink has a src ancestor IFF some src reaches it.
    _src_reachable: set[int] = set()
    _stack = list(src_tags)
    while _stack:
        _t = _stack.pop()
        if _t in _src_reachable:
            continue
        _src_reachable.add(_t)
        _stack.extend(nodes[_t]["children"])
    sinks_with_rng    = sum(1 for s in sinks if s in _src_reachable)
    sinks_without_rng = len(sinks) - sinks_with_rng

    # RC-05 evidence: any src tag whose downstream reaches a keygen-kind
    # derivation tag.
    #
    # Cap the output at MAX_RNG_TO_KEYGEN_PATHS to bound memory in
    # pathological traces (e.g. ransomware that calls BCryptGenRandom in
    # a tight inner loop produces 80k+ source tags, and any reachable
    # keygen multiplies that into millions of (src, kg) tuples).
    #
    # The 1000 cap is an artifact-level memory-safety constant (NOT
    # paper-cited). Justification: (a) RC-05's evidence reads only the
    # *existence* of any rng->keygen path, not the count -- truncation
    # past 1000 cannot change RC-05's verdict, only its diagnostic
    # detail; (b) 1000 is well above the path count of any non-
    # pathological trace observed (max ~40 in the our corpus);
    # (c) `truncated=True` is recorded so downstream consumers can
    # distinguish "exact count" from "cap-bounded".
    MAX_RNG_TO_KEYGEN_PATHS = 1000
    rng_to_keygen_paths: list[dict] = []
    truncated = False
    # distribute the cap across ALL src tags (round-robin)
    # instead of letting the first src tag exhaust the budget. RC-05 only
    # needs existence-of-path evidence, but losing src tags 2..N from the
    # diagnostic output (when src tag 1 alone reaches >cap keygens) hides
    # which RNG sources participate. We still cap at MAX_RNG_TO_KEYGEN_PATHS
    # total; `truncated=True` now means "sample is exhaustive over src tags
    # but capped per-src in round-robin order".
    if src_tags:
        # forward BFS from every src tag
        # derived_via is populated only in the deriv
        # branch (so sink-only and src-only tags never get it). A tag that
        # was produced by a HANDLE_PRODUCER_APIS keygen but only observed
        # via the Pass 1.5 handle-binding (no kind=keygen deriv event
        # under its own tag) would be excluded. Augment keygen_nodes with
        # any node whose born_by api is a HANDLE_PRODUCER_APIS member, so
        # handle-bound keygens are also counted as RC-05 evidence sinks.
        # RC-05 keygen sinks: only APIs that actually GENERATE/derive new key
        # material from entropy count -- NOT context/provider acquisition
        # (CryptAcquireContext / BCryptOpenAlgorithmProvider produce a CSP or
        # algorithm handle, not a key), key import (an externally-supplied key
        # is not RNG-generated), or key duplication. Using the full
        # HANDLE_PRODUCER_APIS here would let a benign rng -> CryptAcquireContext
        # edge spuriously satisfy RC-05's "weak RNG reaches keygen".
        _KEYGEN_APIS = {
            "BCryptGenerateSymmetricKey", "BCryptGenerateKeyPair",
            "BCryptFinalizeKeyPair", "BCryptDeriveKey",
            "CryptGenKey", "CryptDeriveKey",
        }
        def _is_keygen_node(n: dict) -> bool:
            if any(k in KEYGEN_KINDS for _, k in n["derived_via"]):
                return True
            bb = n["born_by"]
            if bb is not None and bb[0] in _KEYGEN_APIS:
                return True
            return False
        keygen_nodes = {t for t, n in nodes.items() if _is_keygen_node(n)}
        seen_pairs: set[tuple[int, int]] = set()
        # Compute reach per src first; then round-robin so every src gets
        # at least one entry before any src gets a second (until cap).
        per_src_reach: list[tuple[int, list[int]]] = []
        for src in src_tags:
            seen: set[int] = set()
            stack = [src]
            while stack:
                t = stack.pop()
                if t in seen:
                    continue
                seen.add(t)
                for c in nodes[t]["children"]:
                    if c not in seen:
                        stack.append(c)
            reach = sorted(seen & keygen_nodes)
            if reach:
                per_src_reach.append((src, reach))
        # Round-robin emit until cap reached.
        cursors = [0] * len(per_src_reach)
        any_progress = True
        while any_progress and len(rng_to_keygen_paths) < MAX_RNG_TO_KEYGEN_PATHS:
            any_progress = False
            for i, (src, reach) in enumerate(per_src_reach):
                if cursors[i] >= len(reach):
                    continue
                kg = reach[cursors[i]]
                cursors[i] += 1
                any_progress = True
                pair = (src, kg)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                rng_to_keygen_paths.append({
                    "rng_tag":    src,
                    "keygen_tag": kg,
                    "keygen_apis": sorted({a for a, k in nodes[kg]["derived_via"]
                                            if k in KEYGEN_KINDS}),
                })
                if len(rng_to_keygen_paths) >= MAX_RNG_TO_KEYGEN_PATHS:
                    truncated = True
                    break
        # If any src still has unconsumed reach entries, mark truncated.
        if not truncated:
            for i, (_src, reach) in enumerate(per_src_reach):
                if cursors[i] < len(reach):
                    truncated = True
                    break

    # Longest path length (DAG depth). Iterative + cycle-safe: a recursive
    # implementation hit RecursionError on traces with deep chains (or
    # cycles introduced by handle reuse in Pass 1.5). We iterate.
    depth_memo: dict[int, int] = {}
    # do NOT write tentative depth_memo[start]=0 or
    # depth_memo[next_parent]=0 — those writes mis-cache a node's depth as
    # 0 even when it has reachable non-cyclic ancestors, and the next call
    # to _depth_iter that reaches them via depth_memo would propagate the
    # wrong value. Cycle detection now uses on_stack only; cyclic parents
    # are excluded from the current node's depth computation via a local
    # `skipped` set, and cyclic-only nodes are left unmemoised so a later
    # caller can attempt their depth from a different start.
    def _depth_iter(start: int) -> int:
        if start in depth_memo:
            return depth_memo[start]
        # DFS with on-stack tracking for cycle detection.
        # stack entry: (tag, parent_iter, skipped_set_for_this_node)
        stack: list = []
        on_stack: set[int] = set()
        stack.append((start, iter(nodes[start]["parents"]), set()))
        on_stack.add(start)
        while stack:
            tag, parent_iter, skipped = stack[-1]
            next_parent = None
            for p in parent_iter:
                if p in depth_memo:
                    continue
                if p in on_stack:
                    # Cycle: skip this parent for the CURRENT node's depth
                    # computation. Do NOT memoise p — its true depth via a
                    # non-cyclic path (if any) is still unknown.
                    skipped.add(p)
                    continue
                next_parent = p
                break
            if next_parent is not None:
                on_stack.add(next_parent)
                stack.append((next_parent, iter(nodes[next_parent]["parents"]), set()))
                continue
            # All parents resolved (or skipped as cyclic) -- compute depth
            # using only the non-skipped, fully-memoised parents.
            parents = nodes[tag]["parents"]
            usable = [depth_memo[p] for p in parents
                       if p in depth_memo and p not in skipped]
            if not usable and skipped:
                # Every parent was skipped as cyclic and none is memoised yet:
                # this node's non-cyclic depth is still unknown, so leave it
                # UNMEMOISED. Caching a wrong 0 here is what made max_chain_depth
                # order-dependent (a cyclic-only node reached first froze at 0). A
                # later entry from a different start node resolves its true depth.
                on_stack.discard(tag)
                stack.pop()
                continue
            if not usable:
                depth_memo[tag] = 0          # genuinely parentless root
            else:
                depth_memo[tag] = 1 + max(usable)
            on_stack.discard(tag)
            stack.pop()
        # Defensive: if start somehow wasn't memoised (e.g. every parent was
        # cyclic and we early-returned), fall back to 0 for the caller.
        return depth_memo.get(start, 0)

    max_depth = 0
    for t in nodes:
        if t not in depth_memo:
            _depth_iter(t)
        max_depth = max(max_depth, depth_memo.get(t, 0))

    # Serialise.
    def _node_serialise(n: dict) -> dict:
        return {
            "tag":              n["tag"],
            "born_by":          (None if n["born_by"] is None
                                  else list(n["born_by"])),
            "parents":          sorted(n["parents"]),
            "children":         sorted(n["children"]),
            "is_src":           n["is_src"],
            "is_sink":          n["is_sink"],
            "is_embedded_root": n["is_embedded_root"],
            "sink_apis":        sorted(n["sink_apis"]),
            "derived_via":      sorted(list(n["derived_via"])),
            "first_bytes_hex":  n["first_bytes_hex"],
        }

    return {
        "nodes":           [_node_serialise(n) for n in nodes.values()],
        "edges":           list(edges.values()),
        "stats": {
            "node_count":             len(nodes),
            "edge_count":             len(edges),
            "source_count":           len(src_tags),
            "embedded_root_count":    len(embedded),
            "sink_count":             len(sinks),
            "sinks_with_rng_ancestor":    sinks_with_rng,
            "sinks_without_rng_ancestor": sinks_without_rng,
            "hardcoded_key_ratio":    (sinks_without_rng / len(sinks)
                                        if sinks else 0.0),
            "max_chain_depth":        max_depth,
            "rng_to_keygen_path_count": len(rng_to_keygen_paths),
            "rng_to_keygen_truncated":  truncated,
        },
        "rng_to_keygen_paths": rng_to_keygen_paths,
        # key=str: a tagless sink is stored under the "__anon_sink__" string
        # sentinel and Pass 2 may also flag it is_embedded_root, so these sets
        # can mix str+int; plain sorted() would raise TypeError and abort the
        # whole trace. key=str sorts deterministically without crashing (the
        # ordered list is diagnostic only; no verdict depends on its order).
        "src_tags":            sorted(src_tags, key=str),
        "sinks":               sorted(sinks, key=str),
        "embedded_roots":      sorted(embedded, key=str),
    }
