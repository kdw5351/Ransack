"""End-to-end driver for one Ransack PinTool trace directory.

Usage:
    python -m analysis.analyze_trace <trace_dir> [--out-dir <dir>] [--bitness 32|64]

Inputs (under <trace_dir>):
    loaded_dlls.json
    loop_events.jsonl
    loop_<N>.json, loop_<N>.bin
    io_events_<N>.jsonl, crypto_events_<N>.jsonl
    ransomflow_done.json

Outputs (default --out-dir == <trace_dir>):
    report.md                     (top level)
    _detail/analysis_report.json
    _detail/behavior_profile.txt
    _detail/case_study.md

The five paper artefacts (flow_report.md / report.md / unified_report.md /
sample_view.json / README.md) are rendered separately by
onHost/report/generate.py, which onHost/run.py drives.
"""
from __future__ import annotations

import argparse
import os
import sys

try:  # keep stdout/stderr UTF-8 so status prints do not crash on cp949/cp1252 consoles
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# Allow running as both a package (`python -m analysis.analyze_trace`) and
# as a plain script (`python analyze_trace.py`).
if __package__ in (None, ""):
    _HERE = os.path.dirname(os.path.abspath(__file__))
    if os.path.dirname(_HERE) not in sys.path:
        sys.path.insert(0, os.path.dirname(_HERE))
    from analysis import (loaders, disasm, loop_classifier,
                            io_summary as io_mod,
                            crypto_summary as crypto_mod,
                            stage_profile as stage_mod,
                            recovery_cases,
                            residue_scanner, report,
                            catalogs as catalogs_mod,
                            cipher_constants, sym_key_inference,
                            cross_axis, chain as chain_mod,
                            loop_clustering)
else:
    from . import (loaders, disasm, loop_classifier,
                    io_summary as io_mod,
                    crypto_summary as crypto_mod,
                    stage_profile as stage_mod,
                    recovery_cases,
                    residue_scanner, report,
                    catalogs as catalogs_mod,
                    cipher_constants, sym_key_inference,
                    cross_axis, chain as chain_mod,
                    loop_clustering)


# Asset catalogues live at <RansackRoot>/assets/ — shared by VM and host.
# This file sits at <RansackRoot>/onHost/analysis/analyze_trace.py, so the
# default path goes up two levels: ../../assets/.
def _default_asset(name: str) -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", "..", "assets", name))


def run(trace_dir: str, out_dir: str | None = None,
         bitness: int | None = None,
         patterns_path: str | None = None,
         roles_path: str | None = None,
         assets_dir: str | None = None,
         verbose: bool = False) -> dict:
    trace_dir = os.path.abspath(trace_dir)
    out_dir   = os.path.abspath(out_dir or trace_dir)
    os.makedirs(out_dir, exist_ok=True)

    patterns_path = patterns_path or _default_asset("loop_patterns.json")
    roles_path    = roles_path    or _default_asset("dll_roles.json")
    assets_dir    = assets_dir    or os.path.dirname(patterns_path)

    # Catalogs are needed for the magic-byte scanner (cipher_constants) and
    # the symmetric-key algorithm inference rules. Loaded once and reused.
    catalogs = catalogs_mod.load_catalogs(assets_dir)

    if verbose:
        print(f"[*] loading trace {trace_dir}")
    bundle = loaders.load_bundle(trace_dir)

    if verbose:
        print(f"[*] loops captured: {len(bundle['loops'])}, "
              f"io_events={len(bundle['io_events'])}, "
              f"crypto_events={len(bundle['crypto_events'])}")

    # Disassemble every loop snapshot in place.
    if verbose:
        print("[*] disassembling loop snapshots")
    for L in bundle["loops"].values():
        b = bitness if bitness is not None else disasm.detect_bitness(L)
        L["_disasm"] = disasm.disasm_loop(L, b)

    if verbose:
        print("[*] applying loop pattern catalog")
    loop_labels = loop_classifier.classify_all(bundle,
                                                patterns_path=patterns_path,
                                                roles_path=roles_path)

    if verbose:
        print("[*] aggregating IO events")
    io_sum     = io_mod.summarize(bundle["io_events"])
    if verbose:
        print("[*] aggregating crypto events")
    # Pass the loop metadata so summarize() can do geometric IP-range
    # attribution for events that the PinTool emitted without a
    # `loop_id` field. (containment of event IP within a
    # captured loop's [header, loop_end) is direct Pin measurement,
    # not inference.)
    crypto_sum = crypto_mod.summarize(bundle["crypto_events"],
                                       loops_meta=bundle.get("loops"))
    # fill sym_keys[i].hex from keybirth snapshots (PinTool dumps
    # the captured key buffer starting at offset 0 of the snapshot file).
    crypto_sum = crypto_mod.enrich_sym_keys_with_snapshots(crypto_sum, bundle)
    # PayBreak-style captured keys that arrive as the plaintext input to an RSA-wrap
    # (an ASCII "KEY|IV" sink_plaintext snapshot, e.g. Chaos) are not keygen/kdf
    # events, so the harvest above misses them. Promote them by their exact structure.
    crypto_sum = crypto_mod.harvest_wrapped_session_keys(crypto_sum, bundle)
    # Split cipher PARAMETERS (chaining mode / IV set via *SetProperty /
    # SetKeyParam) out of the symmetric-key inventory: they were mis-counted as
    # captured keys, and decoded properly they yield the mode + IV a decryptor
    # needs. Must run after the snapshot enrichment above.
    crypto_sum = crypto_mod.partition_cipher_params(crypto_sum)

    if verbose:
        print("[*] building key-derivation chain graph (paper §III)")
    chain = chain_mod.build(bundle["crypto_events"])
    if verbose:
        cs = chain["stats"]
        print(f"    chain: nodes={cs['node_count']} edges={cs['edge_count']} "
              f"sources={cs['source_count']} sinks={cs['sink_count']} "
              f"embedded_roots={cs['embedded_root_count']} "
              f"hardcoded_ratio={cs['hardcoded_key_ratio']:.2f}")

    if verbose:
        print("[*] building stage profile")
    stage = stage_mod.build(bundle, loop_labels, io_sum, crypto_sum)

    if verbose:
        print("[*] scanning loop immediates for cipher magic bytes")
    disasm_by_loop = {lid: L.get("_disasm") or {} for lid, L in bundle["loops"].items()}
    cipher_const_hits = cipher_constants.scan_proc(disasm_by_loop, catalogs)

    if verbose:
        print("[*] cross-axis corroboration (paper §III Step 3)")
    cross_axis_report = cross_axis.corroborate(
        loop_labels=loop_labels,
        crypto_per_loop=crypto_sum.get("per_loop") or {},
        cipher_const_by_loop=cipher_const_hits.get("by_loop") or {},
        crypto_global=crypto_sum)
    if verbose:
        vc = cross_axis_report["verdict_counts"]
        print(f"    verdicts: corroborated={vc['corroborated']} "
              f"byte_gated={vc['byte_gated']} "
              f"pattern_only={vc['pattern_only']} "
              f"downgraded={vc['downgraded']}")

    if verbose:
        print("[*] clustering loops by structural fingerprint")
    clusters = loop_clustering.build(bundle, loop_labels)
    if verbose:
        cstats = clusters["stats"]
        big = cstats.get("largest_cluster") or {}
        print(f"    {cstats['input_loops']} loops → "
              f"{cstats['cluster_count']} clusters "
              f"(compaction={cstats['compaction_ratio']:.2f}); "
              f"largest={big.get('loop_count')}× `{big.get('label')}`")

    if verbose:
        print("[*] inferring algorithms for sym keys without explicit tag")
    sym_key_infer = sym_key_inference.annotate_sym_keys(
        catalogs, crypto_sum.get("sym_keys") or [])
    # Keys harvested at a wrap input stay out of `sym_keys` on purpose (see
    # crypto_summary.harvest_wrapped_session_keys), which also kept them out of
    # the length rules. Run the rules over them separately: a run can hold
    # thousands of captured session keys and otherwise report no cipher at all.
    wrapped_key_infer = sym_key_inference.annotate_sym_keys(
        catalogs, crypto_sum.get("wrapped_session_keys") or [])

    if verbose:
        print("[*] scanning key-birth snapshots for residue")
    residue = residue_scanner.scan(bundle)

    if verbose:
        print(f"[*] residue class = {residue.get('residue_class')} "
              f"({residue.get('total_matches', 0)} matches in "
              f"{residue.get('snapshots_scanned', 0)} snapshots)")

    if verbose:
        print("[*] scanning snapshots for spec-grounded byte signatures "
              "(aeskeyfind / BCRYPT RSA blob magic / Avaddon session key / "
              "wanakiwi prime divisibility)")
    from . import byte_signature_scanner
    # The scanner needs crypto_summary to extract RSA moduli for wanakiwi.
    bundle["crypto_summary"] = crypto_sum
    byte_sigs = byte_signature_scanner.scan_all_snapshots(bundle)
    if verbose:
        print(f"[*] byte signatures: aeskeyfind={byte_sigs['aeskeyfind_count']}, "
              f"bcrypt_rsa_blob={byte_sigs['bcrypt_rsa_blob_count']}, "
              f"cryptoapi_rsa_blob={byte_sigs.get('cryptoapi_rsa_blob_count', 0)}, "
              f"avaddon_session={byte_sigs['avaddon_session_count']}, "
              f"wanakiwi_prime={byte_sigs.get('wanakiwi_prime_count', 0)}")

    # Paper §III: residue class is the strongest observable evidence across
    # all measurement methods. Promote class from byte-sig hits (verbatim
    # published algorithms) so the RC-01/02/03/06 residue conjunctions can
    # reach HIGH even though the PinTool emits buffer POINTERS (not out_buf_hex)
    # and the literal captured-key scan is therefore inactive.
    # NOTE: promotion alone does NOT fire those RCs -- each RC's
    # residue_class_at_least(allowed_byte_sigs=...) reverts a promotion driven
    # by an irrelevant signature (e.g. RC-03 accepts only wanakiwi_prime, so an
    # AES aeskeyfind hit does not satisfy the RSA-keypair RC-02/03).
    residue = residue_scanner.apply_byte_sig_promotion(residue, byte_sigs)
    if verbose and "byte_sig_promotion" in residue:
        prom = residue["byte_sig_promotion"]
        print(f"[*] residue class promoted: {prom['from']} -> {prom['to']} "
              f"({', '.join(prom['reasons'])})")

    if verbose:
        print("[*] evaluating RC-01..RC-07 recovery cases")
    rc = recovery_cases.evaluate({
        "bundle":         bundle,
        "loop_labels":    loop_labels,
        "io_summary":     io_sum,
        "crypto_summary": crypto_sum,
        "trace_dir":      trace_dir,
        "residue":        residue,
        "chain":          chain,
        "byte_sigs":      byte_sigs,
        # RC-06 decisive_cipher_artifact reads non-ambiguous cipher magic
        # constants captured in loop immediates (cipher_constants.scan_proc).
        "cipher_constants": cipher_const_hits,
    })

    if verbose:
        print("[*] writing outputs")
    detail_dir = os.path.join(out_dir, "_detail")
    os.makedirs(detail_dir, exist_ok=True)
    report.write_report(
        os.path.join(out_dir, "report.md"),
        bundle=bundle, loop_labels=loop_labels,
        io_summary=io_sum, crypto_summary=crypto_sum,
        stage_profile=stage,
        recovery=rc,
        residue=residue,
        cipher_constants=cipher_const_hits,
        cross_axis=cross_axis_report,
        chain=chain,
        clusters=clusters,
        byte_sigs=byte_sigs,
    )
    report.write_analysis_report(
        os.path.join(detail_dir, "analysis_report.json"),
        bundle=bundle, loop_labels=loop_labels,
        io_summary=io_sum, crypto_summary=crypto_sum,
        stage_profile=stage, recovery=rc,
        residue=residue,
        cipher_constants=cipher_const_hits,
        sym_key_inference=sym_key_infer,
        wrapped_key_inference=wrapped_key_infer,
        cross_axis=cross_axis_report,
        chain=chain,
        clusters=clusters,
        byte_sigs=byte_sigs,
    )
    report.write_behavior_profile(
        os.path.join(detail_dir, "behavior_profile.txt"), stage)
    report.write_case_study(
        os.path.join(detail_dir, "case_study.md"),
        bundle=bundle, loop_labels=loop_labels,
        io_summary=io_sum, crypto_summary=crypto_sum,
        stage_profile=stage, recovery=rc,
        cipher_constants=cipher_const_hits,
        sym_key_inference=sym_key_infer,
        cross_axis=cross_axis_report,
        chain=chain,
        clusters=clusters,
    )

    if verbose:
        print(f"[*] done. outputs under {out_dir}")
        print(f"      loops={len(loop_labels)} "
              f"rc_passed={rc['passed_count']}/{rc['total_cases']} "
              f"support={rc['support_status']}")

    return {
        "out_dir":           out_dir,
        "bundle":            bundle,
        "loop_labels":       loop_labels,
        "io_summary":        io_sum,
        "crypto_summary":    crypto_sum,
        "stage_profile":     stage,
        "recovery":          rc,
        "residue":           residue,
        "cipher_constants":  cipher_const_hits,
        "sym_key_inference": sym_key_infer,
        "cross_axis":        cross_axis_report,
        "chain":             chain,
        "clusters":          clusters,
        "byte_sigs":         byte_sigs,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("trace_dir", help="PinTool -out_dir to analyze")
    ap.add_argument("--out-dir", default=None,
                     help="where to write analysis_report.json (default: trace_dir)")
    ap.add_argument("--bitness", type=int, choices=(32, 64), default=None,
                     help="force x86 mode for capstone (default: auto-detect)")
    ap.add_argument("--patterns", default=None,
                     help="path to loop_patterns.json (default: <RansackRoot>/assets/)")
    ap.add_argument("--roles", default=None,
                     help="path to dll_roles.json    (default: <RansackRoot>/assets/)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    try:
        run(args.trace_dir, out_dir=args.out_dir, bitness=args.bitness,
             patterns_path=args.patterns, roles_path=args.roles,
             verbose=args.verbose)
    except FileNotFoundError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
