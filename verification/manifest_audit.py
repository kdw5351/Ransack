#!/usr/bin/env python3
"""Audit the released corpus manifest against each trace's own analysis record.

samples.csv states, per sample, which recovery cases matched and whether the
capture was residue-backed.  Every trace also carries the pipeline's own
_analysis/summary.json from the run that produced it.  They should agree.

Writes manifest_audit.json next to this script.
"""
from __future__ import annotations
import os, sys, json, collections

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from tracemap import build  # noqa: E402

# The raw per-sample traces are not shipped with the artifact; point
# RANSACK_TRACE_ROOT at a directory holding them to re-run this audit.
TRACE_ROOT = os.environ.get("RANSACK_TRACE_ROOT", "")
OUT = os.path.join(HERE, "manifest_audit.json")


def summary_for(trace):
    """Aggregate the trace's own analysis record over its processes."""
    p = os.path.join(TRACE_ROOT, trace, "_analysis", "summary.json")
    if not os.path.exists(p):
        return None
    try:
        d = json.load(open(p, encoding="utf-8"))
    except Exception:
        return None
    passed, resid, strategies = 0, "NONE", set()
    order = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
    for _, v in (d.get("procs") or {}).items():
        passed = max(passed, int(v.get("recovery_passed") or 0))
        rc = (v.get("residue_class") or "NONE").upper()
        if order.get(rc, 0) > order.get(resid, 0):
            resid = rc
        for s in (v.get("feasible_strategies") or []):
            strategies.add(str(s))
    return {"passed": passed, "residue_class": resid,
            "strategies": sorted(strategies)}


def main():
    if not TRACE_ROOT:
        raise SystemExit(
            "the raw traces are not part of this artifact; set "
            "RANSACK_TRACE_ROOT to a directory of trace_* directories to "
            "re-run this audit. The recorded result is in manifest_audit.json")
    t2r, recs, unjoined, ambiguous = build()
    assert not unjoined and not ambiguous

    def rcset(r):
        v = r["RC mapping"].strip()
        return set() if not v else {"RC-" + t.strip() for t in v.split(",") if t.strip()}

    by_row = collections.defaultdict(list)
    for t, r in t2r.items():
        by_row[id(r)].append(t)
    id2r = {id(r): r for r in recs}

    rows = []
    for rid, traces in by_row.items():
        r = id2r[rid]
        if r["execution_outcome"] != "Captured evidence":
            continue
        best = {"passed": 0, "residue_class": "NONE", "strategies": []}
        order = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
        seen = False
        for t in traces:
            s = summary_for(t)
            if not s:
                continue
            seen = True
            best["passed"] = max(best["passed"], s["passed"])
            if order.get(s["residue_class"], 0) > order.get(best["residue_class"], 0):
                best["residue_class"] = s["residue_class"]
            best["strategies"] = sorted(set(best["strategies"]) | set(s["strategies"]))
        if not seen:
            continue
        claimed_rc = rcset(r)
        claimed_res = r["Residue-backed"].strip().upper() == "HIGH"
        rows.append({
            "sample": r["sample"], "family": r["_fam"],
            "validated": r["File-encryption validated"].strip().lower() == "o",
            "claimed_cases": sorted(claimed_rc), "claimed_n": len(claimed_rc),
            "trace_passed": best["passed"],
            "claimed_residue_high": claimed_res,
            "trace_residue": best["residue_class"],
            "rc_mismatch": len(claimed_rc) != best["passed"],
            "residue_mismatch": claimed_res != (best["residue_class"] == "HIGH"),
        })

    tot = len(rows)
    rc_bad = [x for x in rows if x["rc_mismatch"]]
    res_bad = [x for x in rows if x["residue_mismatch"]]
    ghost = [x for x in rows if x["claimed_n"] and x["trace_passed"] == 0]
    missed = [x for x in rows if not x["claimed_n"] and x["trace_passed"]]

    out = {"n_captures_audited": tot,
           "rc_count_mismatch": len(rc_bad),
           "residue_mismatch": len(res_bad),
           "claimed_but_trace_shows_none": len(ghost),
           "trace_shows_match_but_not_claimed": len(missed),
           "ghosts": ghost, "missed": missed[:50], "rows": rows}
    json.dump(out, open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)

    print(f"captures audited                       : {tot}")
    print(f"RC count disagrees with trace record   : {len(rc_bad)}")
    print(f"residue flag disagrees                 : {len(res_bad)}")
    print(f"manifest claims a match, trace shows 0 : {len(ghost)}")
    print(f"trace shows a match, manifest claims 0 : {len(missed)}")
    print("\n--- manifest claims a match, trace record shows none ---")
    for x in ghost[:25]:
        print(f"   {x['family']:18} {x['sample']:28} claims {','.join(x['claimed_cases'])}"
              f"  residue={x['trace_residue']}  validated={x['validated']}")
    print(f"\n[+] {OUT}")


if __name__ == "__main__":
    main()
