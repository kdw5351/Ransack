"""Three report writers (flow_report.md, report.md, unified_report.md).

All consume the dict produced by `schema.adapt(...)`. No external state."""
from __future__ import annotations

import re
from collections import defaultdict

from schema import CATEGORY_DESCRIPTIONS


def _humanize_evidence(s: str) -> str:
    """Render the pipeline's internal evidence tokens as plain English for the
    reader-facing dossiers (the raw tokens stay in sample_view.json).

      const~:tea_delta/TEA@loop129   -> tea_delta constant (TEA) at loop 129
      bytesig:avaddon_session(70)     -> avaddon_session byte-signature (70 hits)
      decisive artifacts=1 (incl. ambiguous; needs disambiguation): ['x']
                                      -> 1 decisive cipher artifact, ambiguous
                                         (needs disambiguation): x
    """
    if not s:
        return s
    s = re.sub(r"(?:[Dd]ecisive artifacts=){2,}", "decisive artifacts=", s)
    s = re.sub(r"const~:([A-Za-z0-9_]+)/([A-Za-z0-9]+)@loop(\d+)",
               r"\1 constant (\2) at loop \3", s)
    s = re.sub(r"bytesig:([A-Za-z0-9_]+)\((\d+)\)",
               lambda m: f"{m.group(1)} byte-signature "
                         f"({m.group(2)} hit{'' if m.group(2) == '1' else 's'})", s)
    def _artifacts(n, tail):
        return f"{n} decisive cipher artifact{'' if n == '1' else 's'}{tail}"
    s = re.sub(r"[Dd]ecisive artifacts=(\d+) \(incl\. ambiguous; needs disambiguation\):",
               lambda m: _artifacts(m.group(1), ", ambiguous (needs disambiguation):"), s)
    s = re.sub(r"[Dd]ecisive artifacts=(\d+):",
               lambda m: _artifacts(m.group(1), ":"), s)
    # collapse Python list-repr of quoted strings to a plain comma list

    def _delist(m):
        parts = re.findall(r"'([^']*)'", m.group(1))
        return ", ".join(parts) if parts else m.group(0)
    return re.sub(r"\[([^\[\]]*)\]", _delist, s)

_RUNTIME_SRC = {
    "mtime": "estimated from trace file timestamps",
    "none": "source unavailable",
    "ransomflow_done": "measured at ransomflow completion",
    "analysis_report": "measured from analysis report",
}


def _fmt_num(n) -> str:
    if n is None:
        return "?"
    if isinstance(n, float):
        return f"{n:.2f}".rstrip("0").rstrip(".")
    return str(n)


def _fmt_bytes(b) -> str:
    if b is None:
        return "?"
    if not isinstance(b, (int, float)):
        return str(b)
    units = ["B", "KB", "MB", "GB"]
    val = float(b)
    for u in units:
        if val < 1024 or u == units[-1]:
            return f"{val:.1f} {u}"
        val /= 1024
    return f"{val:.1f} GB"


def _flatten_subgraphs(lines: list[str]) -> list[str]:
    """Render the Stage-10 diagram WITHOUT subgraphs so it renders on GitHub.

    GitHub's bundled Mermaid (dagre layout) raises
    'Could not find a suitable point for the given distance' whenever an edge
    crosses a subgraph boundary -- exactly what this diagram does (the flow
    links nodes across the Key-Sources / Derivation / Inventory / Loops / Sinks
    / Files groups). VS Code's newer Mermaid routes it fine; GitHub's does not.

    Flatten it: turn each ``subgraph ID ["title"] ... end`` into a header node
    ``ID["title"]:::grouphdr`` joined to its members with dotted edges. No
    subgraphs remain, so there is no cross-cluster edge routing and the dagre
    failure cannot occur -- while the group labels, node colours and flow edges
    are all preserved. Idempotent: input with no subgraphs is returned as-is."""
    import re as _re
    sub_re = _re.compile(r'^(\s*)subgraph\s+(\w+)\s+\[(.*)\]\s*$')
    node_re = _re.compile(r'^\s*(\w+)\s*[\[\(\{]')
    out: list[str] = []
    cur = None
    members: list[str] = []
    had_sub = False
    for ln in lines:
        m = sub_re.match(ln)
        if m:
            had_sub = True
            cur = m.group(2)
            members = []
            out.append(f'{m.group(1)}{cur}[{m.group(3)}]:::grouphdr')
            continue
        if cur is not None and ln.strip() == "end":
            for mem in members:
                out.append(f" {cur} -.-> {mem}")
            cur = None
            members = []
            continue
        if cur is not None:
            nm = node_re.match(ln)
            if nm and nm.group(1) != cur:
                members.append(nm.group(1))
        out.append(ln)
    if not had_sub:
        return out
    res: list[str] = []
    for ln in out:
        res.append(ln)
        if ln.strip() == "flowchart TB":
            res.append(" classDef grouphdr fill:#eef2ff,stroke:#7080b0,"
                       "stroke-width:1px,color:#283050,font-weight:bold")
    return res


def _render_stage10_defective(view: dict, eq: str, loops_total: int,
                              rng_total: int, sym_total: int,
                              cipher: str, rec: dict, passed: list,
                              total_clusters: int) -> list[str]:
    """Compact 3-node warning diagram for defective samples (NO_PAYLOAD_RUN /
    pin_attach_failed / sample_traced_but_did_not_encrypt). Matches the
    legacy `_flow_reconstructor.py` format for defective traces."""
    totals = view["totals"]
    return [
        "",
        "## Stage 10 — Integrated Flow Diagram (Mermaid)",
        "",
        "> **Pin trace incomplete** — this sample is in the *defective* bucket "
        f"(`execution_quality = {eq}`). The diagram below shows only what the "
        "partial trace captured; API counters may underrepresent the sample's "
        "actual behaviour. No flow reconstruction is claimed for this sample.",
        "",
        "```mermaid",
        "flowchart TB",
        " classDef warn fill:#fff5e0,stroke:#a06b00,stroke-width:2px,color:#704800",
        " classDef trace fill:#f5f5f5,stroke:#707070,stroke-width:1px,color:#404040",
        " classDef tier fill:#fff,stroke:#202020,stroke-width:2px,color:#000,font-weight:bold",
        "",
        f' W1[" trace incomplete<br/>execution_quality = {eq}<br/>'
        'Pin attach: failed / partial"]:::warn',
        f' T1["Captured (best-effort):<br/>'
        f'writes={totals["writes"]:,} · reads={totals["reads"]:,}<br/>'
        f'RNG={rng_total:,} · sym_encrypt={sym_total:,}<br/>'
        f'hot loops={loops_total} · clusters={total_clusters}"]:::trace',
        f' T2["Tier: {rec["tier"]}<br/>'
        f'primary_cipher: {cipher}<br/>'
        f'strict cases: {len(passed)}/{rec["total_cases"]} passed<br/>'
        f'VALIDATED: {rec["validated"]}"]:::tier',
        " W1 --> T1",
        " T1 --> T2",
        "```",
        "",
        "---",
        "_For defective samples, see `report.md` § Recovery Verdict for the "
        "partial trace's contents. No claim of full flow reconstruction is "
        "made for samples flagged `pin_attach_failed` or `no_payload_run`._",
        "",
    ]


def _sanitize_mermaid_text(s: str) -> str:
    # extend sanitization for Mermaid label-breaking chars
    # (brackets, parens, angle brackets, backticks) so demangled C++ symbols
    # and decorated API names like '__chkstk@8' do not break node literals.
    return (s.replace('"', "'")
             .replace("\n", " ")
             .replace("|", "/")
             .replace("[", "(")
             .replace("]", ")")
             .replace("<", "<")
             .replace(">", ">")
             .replace("`", "'"))


def _render_stage10_graph(view: dict, dll_roles: dict, loops_total: int,
                          loops_crypto: int, total_clusters: int,
                          rng_total: int, sym_total: int, cipher: str,
                          rec: dict, eq: str, passed: list) -> list[str]:
    """Evidence-driven Stage 10. The tree is built from what the trace actually
    captured — only fired APIs, only non-empty loop categories, only matched
    rule labels become nodes. Sample-specific by construction."""
    totals = view["totals"]

    if eq in ("pin_attach_failed", "no_payload_run", "sample_traced_but_did_not_encrypt"):
        return _render_stage10_defective(view, eq, loops_total, rng_total,
                                         sym_total, cipher, rec, passed,
                                         total_clusters)

    ev = view.get("evidence_tree") or {}
    rng_apis = ev.get("rng_apis", {}) or {}
    keygen_apis = ev.get("keygen_apis", {}) or {}
    kdf_apis = ev.get("kdf_apis", {}) or {}
    hash_apis = ev.get("hash_apis", {}) or {}
    key_import = ev.get("key_import", {}) or {}
    key_export = ev.get("key_export", {}) or {}
    sym_sinks = ev.get("sym_sinks", {}) or {}
    asym_sinks = ev.get("asym_sinks", {}) or {}
    chain_src = ev.get("chain_src_apis", {}) or {}
    embedded_roots = ev.get("chain_embedded_root_apis", {}) or {}
    loop_cats = ev.get("loops_categories", []) or []
    inline_cipher_label = ev.get("inline_cipher")
    files = ev.get("files", {}) or {}
    by_kind = ev.get("by_kind", {}) or {}

    out: list[str] = [
        "",
        "## Stage 10 — Integrated Flow Diagram (Mermaid)",
        "",
        "Per-sample evidence tree — every node corresponds to a rule that fired "
        "or an API that was actually called in this trace. APIs that were "
        "hooked but never invoked are omitted; loop categories with 0 clusters "
        "are omitted; file ops with 0 events are omitted.",
        "",
    ]
    out.append("```mermaid")
    out.append("flowchart TB")
    out += [
        " classDef root fill:#e8f4ff,stroke:#0a4f8f,stroke-width:1.5px,color:#0a3070",
        " classDef kdf fill:#fff7e0,stroke:#a06b00,stroke-width:1.5px,color:#704800",
        " classDef cryptol fill:#f0e8ff,stroke:#5a2080,stroke-width:1.5px,color:#3a0e60",
        " classDef antil fill:#ffeae0,stroke:#b04020,stroke-width:1.5px,color:#702010",
        " classDef other fill:#f5f5f5,stroke:#707070,stroke-width:1px,color:#404040",
        " classDef sink fill:#ffe8e8,stroke:#a01010,stroke-width:1.5px,color:#700808",
        " classDef rule fill:#fffae0,stroke:#8a6500,stroke-width:1.5px,color:#503c00",
        " classDef file fill:#e8ffe8,stroke:#107010,stroke-width:1.5px,color:#054005",
        " classDef tier fill:#fff,stroke:#202020,stroke-width:2px,color:#000,font-weight:bold",
        "",
    ]

    rng_nodes: list[str] = []
    if rng_apis:
        out.append(' subgraph SRC ["Key Sources (observed)"]')
        for i, (api, calls) in enumerate(sorted(rng_apis.items(), key=lambda x: -x[1])[:6], 1):
            nid = f"R{i}"
            tag_ct = chain_src.get(api, 0)
            tag_suffix = f"<br/>chain tags={tag_ct}" if tag_ct else ""
            out.append(f' {nid}["{_sanitize_mermaid_text(api)}<br/>'
                       f'{calls:,} calls{tag_suffix}"]:::root')
            rng_nodes.append(nid)
        out.append(" end")
        out.append("")

    kdf_nodes: list[tuple[str, str]] = []
    has_keygen = bool(keygen_apis) or by_kind.get("keygen", 0) > 0
    has_kdf_kind = bool(kdf_apis) or bool(hash_apis) or by_kind.get("kdf", 0) > 0 or by_kind.get("hash", 0) > 0
    has_import = bool(key_import) or by_kind.get("key_import", 0) > 0
    if has_keygen or has_kdf_kind or has_import:
        out.append(' subgraph KDF ["Key Derivation (observed kinds)"]')
        if has_keygen:
            top_keygen = sorted(keygen_apis.items(), key=lambda x: -x[1])[:3]
            apis_str = "<br/>".join(f"{_sanitize_mermaid_text(a)} ({c:,})" for a, c in top_keygen)
            out.append(f' K1["keygen kind<br/>{by_kind.get("keygen", 0):,} events<br/>'
                       f'{apis_str or "—"}"]:::kdf')
            kdf_nodes.append(("K1", "keygen"))
        if has_kdf_kind:
            top_kdf = sorted(list(kdf_apis.items()) + list(hash_apis.items()),
                              key=lambda x: -x[1])[:3]
            apis_str = "<br/>".join(f"{_sanitize_mermaid_text(a)} ({c:,})" for a, c in top_kdf)
            kdf_events = by_kind.get("kdf", 0) + by_kind.get("hash", 0)
            out.append(f' K2["kdf/hash kinds<br/>{kdf_events:,} events<br/>'
                       f'{apis_str or "—"}"]:::kdf')
            kdf_nodes.append(("K2", "kdf"))
        if has_import:
            top_imp = sorted(key_import.items(), key=lambda x: -x[1])[:2]
            apis_str = "<br/>".join(f"{_sanitize_mermaid_text(a)} ({c:,})" for a, c in top_imp)
            out.append(f' K3["key import<br/>{by_kind.get("key_import", 0):,} events<br/>'
                       f'{apis_str or "—"}"]:::kdf')
            kdf_nodes.append(("K3", "import"))
        out.append(" end")
        out.append("")

    out.append(' subgraph INV ["Key Inventory (chain summary)"]')
    out.append(f' I1["depth={view["key_chain_depth"]}<br/>'
               f'sym_keys={totals["sym_keys_unique"]} unique<br/>'
               f'asym_blobs={totals["asym_blobs"]}"]:::kdf')
    if embedded_roots:
        # Use the canonical total (matches Stage 4's embedded_root_count); the
        # per-API dict is only the API-attributed subset, so its sum can be
        # smaller. Showing that subset sum here read as a contradictory count.
        ert = view["totals"].get("embedded_root_count", sum(embedded_roots.values()))
        top_er = sorted(embedded_roots.items(), key=lambda x: -x[1])[:2]
        er_str = ", ".join(f"{_sanitize_mermaid_text(a)}={c}" for a, c in top_er)
        out.append(f' I2["embedded_roots: {ert}<br/>'
                   f'(RC-04 indicator)<br/>top APIs: {er_str}"]:::antil')
    out.append(" end")
    out.append("")

    loop_node_ids: list[tuple[str, str, str]] = []
    if loop_cats:
        out.append(' subgraph LOOPS ["Hot Loop Categories (rule-matched)"]')
        anti_node = None
        crypto_node = None
        fs_node = None
        for i, lc in enumerate(loop_cats[:6], 1):
            cat = lc["cat"]
            style = lc["style"]
            prefix = "LC" if style == "cryptol" else ("LA" if style == "antil"
                     else ("LF" if style == "file" else "LO"))
            nid = f"{prefix}{i}"
            out.append(f' {nid}["{_sanitize_mermaid_text(cat)}<br/>'
                       f'{lc["clusters"]} clusters · {lc["iters"]:,} iters"]:::{style}')
            loop_node_ids.append((nid, cat, style))
            if style == "cryptol" and crypto_node is None:
                crypto_node = nid
            if style == "antil" and anti_node is None:
                anti_node = nid
            if style == "file" and fs_node is None:
                fs_node = nid
        out.append(" end")
        out.append("")
    else:
        crypto_node = anti_node = fs_node = None

    rule_nodes: list[str] = []
    if inline_cipher_label:
        out.append(' subgraph RULES ["Rule Matches"]')
        out.append(f' RX1["inline cipher rule<br/>'
                   f'{_sanitize_mermaid_text(inline_cipher_label)}<br/>'
                   f'(loop-pattern match)"]:::rule')
        rule_nodes.append("RX1")
        out.append(" end")
        out.append("")

    sink_nodes: list[str] = []
    # defensive .get() on totals so a missing schema field
    # does not KeyError; sink_count missing is treated as 0.
    have_sinks = sym_sinks or asym_sinks or key_export or (totals.get("sink_count", 0) or 0) > 0
    if have_sinks:
        out.append(' subgraph SINK ["Encryption Sinks (observed)"]')
        for i, (api, calls) in enumerate(sorted(sym_sinks.items(), key=lambda x: -x[1])[:3], 1):
            nid = f"S{i}"
            out.append(f' {nid}["{_sanitize_mermaid_text(api)}<br/>{calls:,} calls"]:::sink')
            sink_nodes.append(nid)
        offset = len(sink_nodes)
        for i, (api, calls) in enumerate(sorted(asym_sinks.items(), key=lambda x: -x[1])[:2], 1):
            nid = f"S{offset + i}"
            out.append(f' {nid}["{_sanitize_mermaid_text(api)} (asym)<br/>'
                       f'{calls:,} calls"]:::sink')
            sink_nodes.append(nid)
        offset = len(sink_nodes)
        for i, (api, calls) in enumerate(sorted(key_export.items(), key=lambda x: -x[1])[:2], 1):
            nid = f"S{offset + i}"
            out.append(f' {nid}["{_sanitize_mermaid_text(api)} (export)<br/>'
                       f'{calls:,} calls"]:::sink')
            sink_nodes.append(nid)
        out.append(f' ST["encryption sinks<br/>{(totals.get("sink_count", 0) or 0):,} tagged events"]:::sink')
        sink_nodes.append("ST")
        out.append(" end")
        out.append("")

    file_node_ids: list[tuple[str, str]] = []
    if files:
        out.append(' subgraph FILES ["File-System Effects (observed)"]')
        labels = {"reads": "Read", "writes": "Write", "moves": "Rename", "deletes": "Delete"}
        # sort items for deterministic diagram output across runs
        for i, (op, ct) in enumerate(sorted(files.items()), 1):
            nid = f"F{i}"
            out.append(f' {nid}["{labels.get(op, op)}<br/>{ct:,} calls"]:::file')
            file_node_ids.append((nid, op))
        out.append(" end")
        out.append("")

    edges = []
    if kdf_nodes:
        target = kdf_nodes[0][0]
        for rn in rng_nodes:
            edges.append(f" {rn} -- entropy --> {target}")
        for i in range(len(kdf_nodes) - 1):
            edges.append(f" {kdf_nodes[i][0]} -- chains --> {kdf_nodes[i+1][0]}")
        edges.append(f" {kdf_nodes[-1][0]} -- builds --> I1")
    else:
        for rn in rng_nodes:
            edges.append(f" {rn} -.-> I1")
    if embedded_roots:
        edges.append(" I1 -. RC-04 .-> I2")

    if crypto_node:
        edges.append(f" I1 -- key bytes --> {crypto_node}")
        for rid in rule_nodes:
            edges.append(f" {crypto_node} -- matches rule --> {rid}")
    elif rule_nodes:
        edges.append(f" I1 -.-> {rule_nodes[0]}")
    elif loop_node_ids:
        edges.append(f" I1 -. no crypto loop .-> {loop_node_ids[0][0]}")

    if sink_nodes:
        for rid in rule_nodes:
            edges.append(f" {rid} -- inline crypto --> ST")
        if crypto_node and not rule_nodes:
            edges.append(f" {crypto_node} -- inline crypto --> ST")
        for sn in sink_nodes:
            if sn != "ST":
                edges.append(f" {sn} --> ST")

    if file_node_ids:
        write_node = next((n for n, op in file_node_ids if op == "writes"), None)
        if write_node and sink_nodes:
            edges.append(f" ST -- ciphertext --> {write_node}")
        if fs_node:
            for fnid, _op in file_node_ids:
                edges.append(f" {fs_node} -. fs walk .-> {fnid}")

    if anti_node and sink_nodes:
        edges.append(f" {anti_node} -. defensive .-> ST")

    # GitHub Mermaid (dagre) fails to place labels on cross-subgraph edges
    # ("Could not find a suitable point for the given distance") -> emit unlabeled edges.
    import re as _re
    edges = [_re.sub(r' -\. .*? \.-> ', ' -.-> ', _re.sub(r' -- .*? --> ', ' --> ', e))
             for e in edges]
    out.extend(edges)
    out.append("")
    out.append(
        f' T1["Tier: {rec["tier"]}<br/>'
        f'primary cipher: {cipher}<br/>'
        f'strict cases: {len(passed)}/{rec["total_cases"]} passed<br/>'
        f'VALIDATED: {rec["validated"]}"]:::tier'
    )
    anchor = "ST" if sink_nodes else ("I1")
    out.append(f" {anchor} --> T1")
    out.append("```")
    out.append("")
    out.append("---")
    out.append(
        "_Tree structure is built per-sample from the observed key/data-flow "
        "chain, the crypto API/kind tallies, the file-operation counts, and "
        "the loop-pattern rule that matched. Nodes that do not appear here "
        "were never observed in this trace._"
    )
    out.append("")
    return _flatten_subgraphs(out)
    # cleanup: 190 lines of unreachable legacy
    # fixed-template chain-graph code removed. The dynamic per-sample tree
    # build above is the production path; the static fall-back template was
    # never wired into any caller after the chain_graph refactor. Reference
    # copy preserved in git history. If a static
    # template is ever needed again, restore from there.

def write_flow_report(view: dict) -> str:
    """Stage 1..10 narrative — matches `_flow_reconstructor.py` format."""
    out: list[str] = []
    fam = view["family"]
    sid = view["session_id"]
    eq = view["execution_quality"]
    rec = view["recovery"]
    cipher = view["primary_cipher"]
    cipher_conf = view["primary_cipher_confidence"]

    out += [
        f"# Ransomware Flow Reconstruction — `{sid}`",
        f"> Generated by the Ransack report generator on {view['generated_at']}. "
        "Single-page integrated view of the ransomware's full encryption flow, "
        "reconstructed from Ransack pipeline outputs.",
        f"> **session**: `{sid}` • **family tag**: `{fam}`",
        "",
        "---",
        "## Stage 1 — Identity & Execution Quality",
        "| field | value |",
        "|---|---|",
        f"| family tag (declared) | `{fam}` |",
        f"| session_id | `{sid}` |",
        f"| execution_quality | **{eq}** |",
        f"| recovery tier | **{rec['tier']}** "
        f"({rec['passed_count']}/{rec['total_cases']} RC cases matched) |",
        f"| `NO_PAYLOAD_RUN` flag | `{rec['tier'] == 'NO_PAYLOAD_RUN'}` |",
        f"| `VALIDATED` flag | `{rec['validated']}` "
        "_(only engaged after offline ≥50% byte-level round-trip — paper §III)_ |",
        f"| primary cipher | **{cipher}** (confidence {cipher_conf}) |",
        f"| key_chain_depth | {view['key_chain_depth']} |",
        f"| runtime (s) | {_fmt_num(view.get('runtime_sec'))} "
        f"_({_RUNTIME_SRC.get(view.get('runtime_source') or 'none', view.get('runtime_source'))})_ |",
        f"| peak working set | {_fmt_bytes(view.get('peak_wss'))} |",
        f"| PIN attach failed | `{view.get('pin_attach_failed', False)}` |",
        "",
        "## Stage 2 — Initialization",
        "DLL category breakdown:",
        "",
    ]
    dll_roles = view["dll_roles"]
    if dll_roles:
        for role in sorted(dll_roles):
            out.append(f"- **{role}**: {dll_roles[role]} dlls")
    else:
        out.append("- *(no DLLs categorised)*")

    api = view["api_counts"]
    rng_total = view["totals"]["rng_calls"]
    sym_total = view["totals"]["sym_encrypt_calls"]
    out += [
        "",
        "## Stage 3 — Key Root: RNG Sources",
        f"Total RNG calls: **{rng_total}**. Hooked APIs observed:",
        "",
        "| RNG API | count |",
        "|---|---:|",
    ]
    for k in ("BCryptGenRandom", "SystemFunction036", "ProcessPrng",
              "CryptGenRandom", "RtlGenRandom"):
        if api.get(k, 0) > 0:
            out.append(f"| `{k}` | {api[k]} |")
    if rng_total == 0:
        out.append("| *(none observed)* | 0 |")

    out += [
        "",
        "## Stage 4 — Key Derivation Chain",
        # defensive .get() guards so partial/deprecated schemas
        # (e.g. NO_PAYLOAD_RUN where ratio is undefined) do not raise KeyError/TypeError.
        f"Embedded roots + sinks: **{view['totals'].get('embedded_root_count', 0) + view['totals'].get('sink_count', 0)}** "
        f"(embedded_roots={view['totals'].get('embedded_root_count', 0)}, "
        f"sinks={view['totals'].get('sink_count', 0)}). "
        f"`key_chain_depth = {view['key_chain_depth']}` (max nested KDF chain seen). "
        f"`hardcoded_key_ratio = {(view['totals'].get('hardcoded_key_ratio') or 0.0):.2f}` "
        "(fraction of sinks without an RNG ancestor — RC-04 indicator).",
        "",
        "## Stage 5 — Symmetric Key Inventory",
        f"Unique symmetric keys: **{view['totals']['sym_keys_unique']}**. "
        f"Asymmetric key blobs: **{view['totals']['asym_blobs']}**.",
        "",
    ]

    loops_total = view["totals"]["loops_total"]
    loops_crypto = view["totals"]["loops_crypto"]
    by_cat = view["loop_by_category"]
    by_label = view["loop_by_label"]
    total_clusters = sum(c["clusters"] for c in by_cat.values())
    distinct_labels = len(by_label)
    out += [
        "## Stage 6 — Loop Inventory (full ransomware behavior flow)",
        f"Total hot loops: **{loops_total}**, crypto-classified: **{loops_crypto}**.",
        f"Loop compaction: **{total_clusters} clusters** across **{distinct_labels} distinct behavior labels**.",
        "",
        "### 6.1 Behavior distribution by category (full-flow reconstruction)",
        "",
        "| Category | Clusters | Iter weight | Meaning |",
        "|---|---:|---:|---|",
    ]
    cats_sorted = sorted(by_cat.items(), key=lambda x: -x[1]["iters"])
    for cat, info in cats_sorted:
        meaning = CATEGORY_DESCRIPTIONS.get(cat, "—")
        out.append(f"| `{cat}` | {info['clusters']} | {info['iters']} | {meaning} |")

    out += ["", "### 6.2 Per-category breakdown (which loops actually ran in each category)", ""]
    cat_to_labels: dict[str, list[tuple[str, dict]]] = defaultdict(list)
    for lab, info in by_label.items():
        cat_to_labels[info["category"]].append((lab, info))
    for cat, _ in cats_sorted:
        meaning = CATEGORY_DESCRIPTIONS.get(cat, "—")
        labels = sorted(cat_to_labels.get(cat, []), key=lambda x: -x[1]["iters"])
        out += [
            f"#### `{cat}` — {meaning}",
            "",
            "| label | clusters | iters |",
            "|---|---:|---:|",
        ]
        for lab, info in labels[:10]:
            out.append(f"| `{lab}` | {info['clusters']} | {info['iters']} |")
        out.append("")

    out += ["### 6.3 Top 10 scored loops (algorithm identification candidates)", "",
            "| score | label | iters | header IP | cluster id |",
            "|---:|---|---:|---|---|"]
    for lp in view["top_scored_loops"]:
        hdr = lp.get("header") or ""
        cid = lp.get("cluster_id") or ""
        out.append(f"| {lp['score']} | `{lp['label']}` | {lp['iters']} | `{hdr}` | `{cid}` |")

    out += [
        "",
        "## Stage 7 — Encryption Sink Events",
        f"The key/data-flow chain records **{view['totals']['sink_count']}** sink events. "
        f"Direct API calls hooked: `BCryptEncrypt`={api.get('BCryptEncrypt', 0)}, "
        f"`CryptEncrypt`={api.get('CryptEncrypt', 0)}, "
        f"`BCryptExportKey`={api.get('BCryptExportKey', 0)}, "
        f"`CryptExportKey`={api.get('CryptExportKey', 0)}.",
        "",
        "## Stage 8 — File-System Operations",
        "| operation | count |",
        "|---|---:|",
        f"| writes | {view['totals']['writes']} |",
        f"| reads | {view['totals']['reads']} |",
        f"| renames | {view['totals']['moves']} |",
        f"| deletes | {view['totals']['deletes']} |",
        "",
        "## Stage 9 — Recovery Feasibility (paper §III)",
        f"- **Tier**: `{rec['tier']}` · "
        f"`NO_PAYLOAD_RUN`={rec['tier'] == 'NO_PAYLOAD_RUN'} · "
        f"`VALIDATED`={rec['validated']}",
        f"- **Strict cases passed**: {rec['passed_count']}/{rec['total_cases']}",
    ]
    # defensive .get() to survive NO_PAYLOAD_RUN short-circuit
    # where schema.adapt may omit passed_cases.
    passed = rec.get("passed_cases") or []
    if passed:
        out.append(f"- **Strict cases fired**: {', '.join('`'+(c['case_id'] or '')+'`' for c in passed)}")
    else:
        out.append("- **Strict cases fired**: (none)")
    out.append(
        f"- **Memory residue**: class={view['residue']['class']}, "
        f"matches={view['residue']['total_matches']}, "
        f"unique_tags={view['residue']['unique_tags_with_hit']}, "
        f"snapshots_scanned={view['residue']['snapshots_scanned']}"
    )

    out += _render_stage10_graph(view, dll_roles, loops_total, loops_crypto,
                                 total_clusters, rng_total, sym_total,
                                 cipher, rec, eq, passed)
    return "\n".join(out)


RC_LITERATURE = {
    "RC-01": ("rsa_private_blob_exported_full", 0.98, "asym_priv_universal",
              "Suiche, M. — wanakiwi technical writeup (2017); Trellix — Avaddon (2021)"),
    "RC-02": ("per_run_rsa_keypair_in_heap", 0.85, "memory_residue_scan",
              "Bajpai & Enbody — Dissecting .NET Ransom (2018); Kolodenker et al. — PayBreak (2017)"),
    "RC-03": ("memory_residue_prime_scan_cryptoapi", 0.55, "memory_residue_scan",
              "Suiche, M. — WannaCry: Decrypting files (2017); Guinet, A. — wannakey (2017)"),
    "RC-04": ("untraced_symmetric_key_root", 0.95, "untraced_root_replay",
              "Bajpai & Enbody — Empirical Study of Key (2020); Securelist — CryptoLocker (2014)"),
    "RC-05": ("weak_predictable_rng_seed", 0.70, "rng_seed_replay",
              "AVAST Decoded — Bart ransomware decryptor (2016); Hasherezade — Petya v1 Salsa20 (2016)"),
    "RC-06": ("decisive_cipher_artifact_captured", 0.65, "concrete_artifact_to_cipher_id",
              "Wheeler & Needham — TEA (1994); Halderman et al. — Lest We Remember (2008)"),
    "RC-07": ("captured_symmetric_session_keys", 0.95, "sym_brute_correlation",
              "Kolodenker et al. — PayBreak (2017); Continella et al. — ShieldFS (2016)"),
}


def write_paper_report(view: dict) -> str:
    """report.md — paper_evidence-style per-sample dossier."""
    out: list[str] = []
    fam = view["family"]
    sid = view["session_id"]
    eq = view["execution_quality"]
    rec = view["recovery"]
    api = view["api_counts"]
    totals = view["totals"]
    pm = view["paper_metrics"]

    out += [
        f"# Paper Evidence: `{fam}` / `{sid}`",
        "",
        f"> Generated by the Ransack report generator on {view['generated_at']}. "
        "Built on top of Intel Pin DBI [Luk et al. 2005, ACM PLDI]. "
        "All technical claims (algorithm names, API references, blob formats, recovery cases) are "
        "backed by an inline spec/literature citation. "
        "See **§ References** at the bottom.",
        "",
        "## 1. Identity",
        "",
        "| key | value |",
        "|---|---|",
        f"| family | `{fam}` |",
        f"| session_id | `{sid}` |",
        f"| execution_quality | `{eq}` |",
        f"| runtime_sec | `{_fmt_num(view.get('runtime_sec'))}` "
        f"_({_RUNTIME_SRC.get(view.get('runtime_source') or 'none', view.get('runtime_source'))})_ |",
        f"| crypto_executed | `{eq in ('encrypted_complete', 'encrypted_partial')}` |",
        f"| coverage notes | `{', '.join(view.get('coverage_notes') or []) or '(none)'}` |",
        "",
        "## 2. Per-Sample Verdict (three paper metrics)",
        "",
        "| metric | result |",
        "|---|---|",
        f"| Key Detection | {pm['key_detection']} |",
        f"| File Recoverability | {pm['file_recoverable']} |",
        f"| Loop-Based Behavior Recovery | {pm['loop_recovery']} |",
        "",
        "## 3. Recovery Assessment (paper §III)",
        "",
        f"- **Tier**: `{rec['tier']}` "
        f"({rec['passed_count']}/{rec['total_cases']} strict cases passed)",
        f"- **`NO_PAYLOAD_RUN`** flag: `{rec['tier'] == 'NO_PAYLOAD_RUN'}` "
        "_(paper §III: sample never executed an encryption pass — re-run rather than read a vacuous decision)_",
        f"- **`VALIDATED`** flag: `{rec['validated']}` "
        "_(paper §III: only engaged after offline byte-level round-trip recovers ≥50% of captured "
        "ciphertexts — never set by this pipeline)_",
        "",
        "**Evidence-axis breakdown** (paper §III — each row is a primitive an RC case keys on; "
        "the values here are what an RC conjunction would have seen).",
        "",
        "| evidence primitive | observation | which RC keys on it |",
        "|---|---|---|",
        f"| `asym_priv_capture` | asym_blobs={totals.get('asym_blobs', 0)}; "
        # api dict may not contain every hooked export
        # API (schema.adapt does not strictly guarantee all keys); use
        # .get(..., 0) to avoid KeyError.
        f"export_apis={api.get('BCryptExportKey', 0) + api.get('CryptExportKey', 0)} | RC-01, RC-02 |",
        f"| `memory_residue` | class={view['residue']['class']}, "
        f"matches={view['residue']['total_matches']}, "
        f"snapshots={view['residue']['snapshots_scanned']} | RC-02, RC-03, RC-06 |",
        f"| `sym_keys_inline` | unique={totals['sym_keys_unique']} | RC-04, RC-07 |",
        f"| `hardcoded_keys` | hardcoded_key_ratio={totals['hardcoded_key_ratio']:.2f} "
        f"| RC-04 |",
        f"| `weak_rng` | rng_calls={totals['rng_calls']}; "
        f"chain_depth={view['key_chain_depth']} | RC-05 |",
        f"| `key_infra_no_sink` | sinks={totals['sink_count']}, "
        f"embedded_roots={totals['embedded_root_count']} | RC-07 |",
        "",
        "## 4. Behaviour Signature (hooked API counts)",
        "",
        "| API | count |",
        "|---|---:|",
    ]
    for name, ct in api.items():
        if ct > 0:
            out.append(f"| `{name}` | {ct} |")
    if not any(v > 0 for v in api.values()):
        out.append("| *(no hooked API observed)* | 0 |")

    out += [
        "",
        "## 5. File Operations",
        "",
        "| metric | value |",
        "|---|---|",
        f"| writes | {totals['writes']} |",
        f"| reads | {totals['reads']} |",
        f"| renames | {totals['moves']} |",
        f"| deletes | {totals['deletes']} |",
        "",
        "## 6. Loop Pipeline",
        "",
        "| metric | value |",
        "|---|---|",
        f"| total hot loops | {totals['loops_total']} |",
        f"| crypto-labelled loops (among top-10 scored) | {totals['loops_crypto']} |",
        f"| loop clusters (distinct labels) | {len(view['loop_by_label'])} |",
        f"| corroborated verdicts | {view['cross_axis'].get('corroborated', 0)} |",
        f"| byte-gated verdicts | {view['cross_axis'].get('byte_gated', 0)} |",
        f"| pattern-only verdicts | {view['cross_axis'].get('pattern_only', 0)} |",
        f"| downgraded verdicts | {view['cross_axis'].get('downgraded', 0)} |",
        "",
        "### 6.1 Cluster compaction by behaviour label",
        "",
        "| behaviour label | clusters | iter weight | category |",
        "|---|---:|---:|---|",
    ]
    labels_sorted = sorted(view["loop_by_label"].items(), key=lambda x: -x[1]["iters"])
    for lab, info in labels_sorted[:25]:
        out.append(f"| `{lab}` | {info['clusters']} | {info['iters']} | {info['category']} |")

    out += [
        "",
        "### 6.2 Top 10 scored loops",
        "",
        "| score | label | iters | header IP | cluster id |",
        "|---:|---|---:|---|---|",
    ]
    for lp in view["top_scored_loops"]:
        hdr = lp.get("header") or ""
        cid = lp.get("cluster_id") or ""
        out.append(f"| {lp['score']} | `{lp['label']}` | {lp['iters']} | `{hdr}` | `{cid}` |")

    out += [
        "",
        "## 7. Memory Residue",
        "",
        "| metric | value |",
        "|---|---|",
        f"| RSA blobs captured | {totals['asym_blobs']} |",
        f"| Sym keys captured (unique hex) | {totals['sym_keys_unique']} |",
        f"| RNG sources | {totals['rng_calls']} |",
        f"| sinks (chain) | {totals['sink_count']} |",
        f"| residue class | {view['residue']['class']} |",
        f"| residue matches | {view['residue']['total_matches']} |",
        f"| snapshots scanned | {view['residue']['snapshots_scanned']} |",
        "",
        "## 8. Detection Gaps (paper §V-A)",
        "",
        "Each row records a limitation that, when it fires, explains why evidence may be "
        "missing for this sample. Codes follow the paper §V-A "
        "limitations taxonomy.",
        "",
        "| code | triggered | note |",
        "|---|:---:|---|",
    ]
    gap_rows = []
    pin_failed = eq in ("no_payload_run", "pin_attach_failed") or view.get("pin_attach_failed")
    gap_rows.append((
        "EXEC_QUALITY_NO_PAYLOAD",
        pin_failed,
        "Increase the execution-time budget; confirm the tracer attached to the correct process; check for anti-debug bailout.",
    ))
    # Strict `anti.` / `anti-` / `anti_` prefix match (rather than substring on
    # "anti") so a catalog label such as `crypto.antiparser_loop` does not
    # falsely trigger the anti-analysis row. The live catalog dot-namespaces
    # these labels (e.g. `anti.short_loop`, `anti.spinlock_pause`).
    has_anti = any(
        (lbl := (l.get("label") or "")).startswith(("anti.", "anti-", "anti_"))
        for l in view["top_scored_loops"]
    )
    gap_rows.append((
        "ANTI_ANALYSIS_LOOPS_DETECTED",
        has_anti,
        "Run with anti-instrumentation countermeasures; intercept anti-debug probes "
        "(IsDebuggerPresent, NtQueryInformationProcess) and return benign values.",
    ))
    gap_rows.append((
        "SAMPLE_IMG_NOT_INSTRUMENTED",
        eq == "pin_attach_failed",
        "Add Windows late-load image hooks (NtMapViewOfSection, LdrLoadDll) so image-mapping "
        "patterns get instrumented.",
    ))
    # defensive .get() so partial traces missing sink_count
    # or rng_calls do not KeyError on gap-row construction.
    sink_no_rng = totals.get("sink_count", 0) > 0 and totals.get("rng_calls", 0) == 0
    gap_rows.append((
        "KEY_CHAIN_DEPTH_ZERO_WITH_SIGNALS",
        sink_no_rng,
        "A memory-copy/key-duplication primitive "
        "(memcpy, RtlMoveMemory, BCryptDuplicateKey) was not followed in the "
        "key-derivation chain, which can over-credit RC-04.",
    ))
    # combine dll_role tags with loop labels.
    # Prior bug: coverage_notes is a list of tag strings (e.g. "anti_dbg"),
    # not a list of file paths, so the membership test was always False.
    # the pipeline already applies the fix: it combines dll_roles keys
    # with loaded_dlls to obtain the actual loaded-DLL set.
    _dll_basenames = list((view.get("dll_roles") or {}).keys()) \
                     + list(view.get("loaded_dlls") or [])
    pyd_loaded = any(str(d).lower().endswith(".pyd") for d in _dll_basenames)
    gap_rows.append((
        "PYD_NOT_REGISTERED",
        pyd_loaded,
        "PyCryptodome's compiled crypto extensions (.pyd) were not registered as "
        "crypto sinks, so the module surfaced no key sink.",
    ))
    residue_dry = view["residue"]["class"] == "NONE" and totals["rng_calls"] > 0
    gap_rows.append((
        "RESIDUE_DRY_WITH_RNG",
        residue_dry,
        "RNG fired but no residue snapshot matched — the key was likely zeroed "
        "mid-encryption.",
    ))

    fired_any = False
    for code, fired, fix in gap_rows:
        mark = "✓" if fired else "—"
        if fired:
            fired_any = True
        out.append(f"| `{code}` | {mark} | {fix} |")
    if not fired_any:
        out.append("| *(no gap codes triggered)* | — | — |")

    out += [
        "",
        "## 9. Strict Recovery Cases (RC-01..RC-07)",
        "",
        f"- **Passed**: {rec['passed_count']} / {rec['total_cases']}",
        f"- **Recoverable (strict)**: {'Yes' if rec['passed_count'] > 0 else 'No'}",
        "",
        "| case | name | passed | confidence | strategy | key literature |",
        "|---|---|:---:|---:|---|---|",
    ]
    passed_ids = {(c["case_id"] or "") for c in rec["passed_cases"]}
    for rid in sorted(RC_LITERATURE):
        name, conf, strategy, lit = RC_LITERATURE[rid]
        mark = "✓" if rid in passed_ids else "—"
        out.append(f"| `{rid}` | {name} | {mark} | {conf} | `{strategy}` | {lit} |")

    # Recovery values for passed RCs — concrete value an operator would
    # feed into the matching decryption strategy. §9 subsections are
    # numbered dynamically so there is no gap when the 9.1/9.2 passed-RC
    # blocks are absent for a 0-pass sample.
    sub9 = 0
    if rec["passed_cases"]:
        sub9 += 1
        out += [
            "",
            f"### 9.{sub9} Recovery values for passed RCs",
            "",
            "For each RC that fired, the block below lists the concrete "
            "value an operator would feed into the matching decryption "
            "strategy. Values are extracted from the captured "
            "cryptographic-state and memory-residue records.",
            "",
        ]
        for c in rec["passed_cases"]:
            out.append(f"#### `{c['case_id']}` — `{c['strategy']}`")
            details = c.get("recovery_details") or []
            if not details:
                out.append(f"- {_humanize_evidence(c.get('recovery_value')) or '—'}")
            else:
                for item in details:
                    label = item.get("label") or ""
                    value = _humanize_evidence(item.get("value") or "")
                    out.append(f"- **{label}**: {value or '(none)'}")
            out.append("")

        # Matched evidence per passed RC — primitive-level proof
        sub9 += 1
        out += [
            "",
            f"### 9.{sub9} Matched evidence per passed RC",
            "",
            "Per-primitive observations that satisfied each RC conjunction.",
            "",
        ]
        for c in rec["passed_cases"]:
            ev_list = c.get("evidence_matched") or []
            out.append(f"**`{c['case_id']}` — {c['name']}**")
            if not ev_list:
                out.append("- (no evidence detail)")
            else:
                for e in ev_list:
                    obs = _humanize_evidence(str(e.get("observed") or "")).replace("|", "\\|")
                    out.append(f"- `{e.get('primitive')}` → {obs}")
            out.append("")

    # Behavioral evidence — process / network / anti-debug.
    behav = view.get("behavioral") or {}
    if behav:
        sub9 += 1
        out += [
            "",
            f"### 9.{sub9} Behavioral evidence (process / network / anti-debug)",
            "",
            "Complements §5 (File Operations) with categories that the "
            "file-op counters do not cover. Visible regardless of RC fire.",
            "",
            "| category | total calls | unique APIs | top APIs (count) |",
            "|---|---:|---:|---|",
        ]
        labels = {
            "Injection":    "Process injection",
            "C2_Network":   "C2 network",
            "AntiAnalysis": "Anti-debug / VM detect",
        }
        for cat in ("Injection", "C2_Network", "AntiAnalysis"):
            ent = behav.get(cat)
            if ent:
                top = ", ".join(f"`{x['api']}`={x['count']}" for x in ent.get("top_apis", []))
                out.append(f"| {labels[cat]} | {ent['total']} | {ent['api_count']} | {top} |")
            else:
                out.append(f"| {labels[cat]} | 0 | 0 | (none observed) |")
        rename_ent = behav.get("FileRename") or {}
        ntset = next((x for x in rename_ent.get("top_apis", [])
                       if x.get("api") == "NtSetInformationFile"), None)
        if ntset:
            out += [
                "",
                f"> **`NtSetInformationFile`** called `{ntset['count']}` "
                f"times — §5 `renames` only counts `MoveFileW` + `MoveFileExW`. "
                f"When invoked with `FileInformationClass = FileRenameInformation`, "
                f"this is a rename. PinTool does not currently dereference the "
                f"argument; treat as upper bound on additional raw-API renames.",
            ]
        gaps = behav.get("_pintool_gaps") or []
        if gaps:
            out += [
                "",
                f"> **PinTool capture gap**: the categories "
                f"{', '.join(f'`{g}`' for g in gaps)} are not currently hooked "
                "by the PinTool instrumentation — `0 observed` here means the "
                "API was never called *or* was called but not captured.",
            ]

    # Evasion-suspected detector
    evasion = view.get("evasion") or {}
    if evasion:
        sub9 += 1
        out += ["", f"### 9.{sub9} Anti-analysis evasion risk", ""]
        if evasion.get("suspected"):
            out += [
                "**EVASION SUSPECTED** — this sample exhibits no "
                "(or near-zero) actual encryption activity despite running "
                "to completion under PinTool. Likely cause: anti-DBI / "
                "anti-VM bailout (sample detects instrumentation and "
                "silently exits or sleeps to time out the harness).",
                "",
                f"- **Trigger flags**: {', '.join(f'`{f}`' for f in evasion.get('flags', []))}",
                f"- Encryption calls observed: `{evasion.get('encrypt_calls', 0)}`",
                f"- File writes observed: `{evasion.get('file_writes', 0)}`",
                f"- RNG calls: `{evasion.get('rng_calls', 0)}` "
                  f"(ratio {evasion.get('rng_ratio', 0.0):.2f})",
                f"- Sleep / delay calls: `{evasion.get('sleep_calls', 0)}`",
            ]
        else:
            out += [
                "**Status: not evasion-suspected.** The sample ran to "
                "completion with encryption activity in this trace "
                "(via hot loops and/or CryptoAPI).",
                "",
                f"- CryptoAPI encryption calls: `{evasion.get('encrypt_calls', 0)}` (0 = custom in-code cipher)",
                f"- File writes: `{evasion.get('file_writes', 0)}`",
            ]

    out += [
        "",
        "## 10. Decryption Tool Synthesis Evidence",
        "",
        "Pipeline signals that inform decryptor synthesis: the detected cipher, its round count, and the I/O chunk size.",
        "",
        "### 10.1 Cipher detection (from crypto-labelled loops)",
        "",
        f"- **Status**: `{'detected' if any((l.get('label') or '').startswith('crypto.') for l in view['top_scored_loops']) else 'not_detected'}`",
        f"- **Primary cipher**: `{view['primary_cipher']}` (confidence {view['primary_cipher_confidence']})",
        "",
        "### 10.2 Round count observation",
        "",
    ]
    # .get('label') or '' so a None label (some PinTool
    # outputs leave it null for unclassified loops) doesn't crash report
    # generation with AttributeError.
    crypto_loops = [l for l in view["top_scored_loops"] if (l.get("label") or "").startswith("crypto.")]
    if crypto_loops:
        out += [
            f"- **Status**: `detected` ({len(crypto_loops)} crypto-labeled loops in top 10)",
            "",
            "| cluster | label | observed iters | header IP |",
            "|---|---|---:|---|",
        ]
        for l in crypto_loops:
            out.append(f"| `{l.get('cluster_id') or ''}` | `{l['label']}` | {l['iters']} | `{l.get('header') or ''}` |")
    else:
        out.append("- **Status**: `not_detected` (no crypto-labeled loops in scored set)")

    out += [
        "",
        "### 10.3 I/O chunk size analysis",
        "",
        f"- **Status**: `{'detected' if totals['writes'] > 0 else 'not_detected'}`",
        f"- writes_total: {totals['writes']}, deletes_total: {totals['deletes']}",
        "",
        "## References",
        "",
        "All technical claims in this dossier are grounded in either an international standard "
        "(NIST FIPS, RFC, IEEE, ISO/IEC), a peer-reviewed paper (USENIX, ACM, Elsevier, IEEE), "
        "official vendor documentation (Microsoft Learn, Intel SDM), or a published "
        "decryptor/analysis from a recognised vendor (Bitdefender, ESET, AVAST, Trend Micro, Trellix, "
        "Comae, Mandiant, AdvIntel, CISA).",
        "",
        "- **Luk C-K. et al., Pin: Building Customized Program Analysis Tools with Dynamic Instrumentation** "
        "(2005) — ACM PLDI 2005 — <https://doi.org/10.1145/1065010.1065034>",
        "- **NIST FIPS 197** — Advanced Encryption Standard (AES).",
        "- **RFC 7539** — ChaCha20 and Poly1305 for IETF Protocols.",
        "- **Wheeler & Needham, TEA: A Tiny Encryption Algorithm** (FSE 1994).",
        "- **Kolodenker E. et al., PayBreak: Defense Against Cryptographic Ransomware** (AsiaCCS 2017).",
        "- **Continella A. et al., ShieldFS: A Self-healing, Ransomware-aware Filesystem** (ACSAC 2016).",
        "",
    ]
    return "\n".join(out)


def write_unified_report(view: dict) -> str:
    """unified_report.md — consolidates flow_report + report into one paper-aligned view."""
    out: list[str] = []
    fam = view["family"]
    sid = view["session_id"]
    eq = view["execution_quality"]
    rec = view["recovery"]
    totals = view["totals"]
    api = view["api_counts"]
    pm = view["paper_metrics"]

    out += [
        f"# Sample Report — `{sid}`",
        "",
        "> Unified per-sample evidence report. Consolidates paper-grade citation-backed "
        "evidence with execution-order timeline and per-loop behavior categorization. "
        "All numerical claims here align with the **RANSACK per-sample metrics** "
        "(Key Detection / File Recoverability / Loop-Based Behavior Recovery).",
        "",
        "## 1. Identity",
        "",
        "| field | value |",
        "|---|---|",
        f"| family tag | `{fam}` |",
        f"| session | `{sid}` |",
        f"| execution_quality | **{eq}** |",
        f"| recovery tier | **{rec['tier']}** "
        f"({rec['passed_count']}/{rec['total_cases']} RC cases matched) |",
        f"| `NO_PAYLOAD_RUN` flag | `{rec['tier'] == 'NO_PAYLOAD_RUN'}` |",
        f"| `VALIDATED` flag | `{rec['validated']}` |",
        f"| primary cipher | **{view['primary_cipher']}** |",
        f"| key_chain_depth | {view['key_chain_depth']} |",
        f"| runtime_sec | {_fmt_num(view.get('runtime_sec'))} |",
        "",
        "## 2. Recovery Verdict (paper PRIMARY metric)",
        "",
    ]
    if rec["passed_cases"]:
        case_ids = ", ".join(f"`{c['case_id']}`" for c in rec["passed_cases"])
        out.append(f"- **strict RC checklist (RC-01..RC-07)**: {case_ids}")
    else:
        out.append("- **strict RC checklist (RC-01..RC-07)**: `(none fired)` — falls into the confident no-match bucket")

    out += [
        f"- **Loop-Based Crypto Behavior Identification**: {pm['loop_recovery']} "
        f"(primary cipher = `{view['primary_cipher']}`)",
        f"- **Key Detection** (any of: captured asymmetric private key, memory-residue key, inline symmetric key, hardcoded key, or RNG output): "
        f"{pm['key_detection']}",
        f"- **File Recoverability**: {pm['file_recoverable']}",
        "",
        "## 3. Cryptographic Behavior (API trace)",
        "",
        "| metric | count | spec/source |",
        "|---|---:|---|",
        f"| RNG calls | {totals['rng_calls']} | "
        "FIPS-140-2 §4.6 (NIST SP 800-90A); MS Learn CNG/CryptoAPI |",
        f"| Sym encrypt calls | {totals['sym_encrypt_calls']} | "
        "MS Learn BCryptEncrypt; FIPS-197 (AES) |",
        f"| Asym blobs captured | {totals['asym_blobs']} | "
        "MS Learn BCryptExportKey; PKCS#1 |",
        f"| Unique sym keys (chain) | {totals['sym_keys_unique']} | "
        "RFC 5246 / FIPS-197 |",
        f"| KDF chain depth | {view['key_chain_depth']} | "
        "RFC 2104 (HMAC) / RFC 5869 (HKDF) |",
        f"| Hardcoded-key ratio | {totals['hardcoded_key_ratio']:.2f} | "
        "RC-04 indicator (Bajpai & Enbody 2020) |",
        "",
        "## 4. File Operations",
        "",
        "| op | count |",
        "|---|---:|",
        f"| writes | {totals['writes']} |",
        f"| reads | {totals['reads']} |",
        f"| renames | {totals['moves']} |",
        f"| deletes | {totals['deletes']} |",
        "",
        "## 5. Loop Behavior Category Breakdown",
        "",
        "> 14-category classification from Ransack loop classifier, spec-grounded via "
        "the loop-pattern and cipher-constant catalogs.",
        "",
        "| Category | Clusters | Iter weight | Meaning |",
        "|---|---:|---:|---|",
    ]
    cats_sorted = sorted(view["loop_by_category"].items(), key=lambda x: -x[1]["iters"])
    for cat, info in cats_sorted:
        meaning = CATEGORY_DESCRIPTIONS.get(cat, "—")
        out.append(f"| `{cat}` | {info['clusters']} | {info['iters']} | {meaning} |")

    out += [
        "",
        "## 6. Execution-Order Timeline (top 10 scored loops)",
        "",
        "> Per-loop scoring weights iteration count, crypto-call density, and classifier confidence.",
        "",
        "| rank | score | label | iters | header IP | cluster id | module |",
        "|---:|---:|---|---:|---|---|---|",
    ]
    for i, lp in enumerate(view["top_scored_loops"], 1):
        out.append(
            f"| {i} | {lp['score']} | `{lp['label']}` | {lp['iters']} | "
            f"`{lp.get('header') or ''}` | `{lp.get('cluster_id') or ''}` | "
            f"`{lp.get('image_module') or ''}` |"
        )

    out += [
        "",
        "## 7. References — Per-Claim Citation Map",
        "",
        "All technical claims in this dossier are grounded in international standards, peer-reviewed "
        "papers, official vendor documentation, or published decryptor/analysis from recognised vendors.",
        "",
        "- **Luk C-K. et al., Pin: Building Customized Program Analysis Tools with Dynamic Instrumentation** "
        "(2005) — ACM PLDI 2005 — <https://doi.org/10.1145/1065010.1065034>",
        "- **NIST FIPS 197** — Advanced Encryption Standard (AES).",
        "- **RFC 7539** — ChaCha20 and Poly1305 for IETF Protocols.",
        "- **FIPS 180-4** — Secure Hash Standard (SHS).",
        "- **Kolodenker E. et al., PayBreak: Defense Against Cryptographic Ransomware** (AsiaCCS 2017).",
        "- **Continella A. et al., ShieldFS: A Self-healing, Ransomware-aware Filesystem** (ACSAC 2016).",
        "- **Halderman et al., Lest We Remember: Cold-Boot Attacks on Encryption Keys** (USENIX Sec 2008).",
        "",
        "---",
        f"_Generated by the Ransack report generator from pipeline outputs. "
        f"See also `flow_report.md` and `report.md`._",
        "",
    ]
    return "\n".join(out)
