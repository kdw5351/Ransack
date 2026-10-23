#!/usr/bin/env python3
"""Join the extracted ablation traces to the paper's samples.csv.

Importable: `from tracemap import build` -> (trace2rec, recs).
Run directly for the join report and the execution-outcome cross-check.
"""
import csv, os, re, glob, collections

_HERE = os.path.dirname(os.path.abspath(__file__))

# The manifest ships with the artifact, next to this directory.
CSV = os.environ.get(
    "RANSACK_SAMPLES_CSV",
    os.path.normpath(os.path.join(_HERE, os.pardir, "data", "samples.csv")))

# The extracted per-sample traces are NOT shipped: the raw-trace corpus exceeds
# the artifact's storage. Point RANSACK_EXTRACTED at a directory holding them to
# reproduce the joins; without it the scripts report that the input is missing.
EXT = os.environ.get("RANSACK_EXTRACTED", "")

ALIAS = {"redaler": "redalert"}          # trace names the harness truncated


def norm(s):
    s = s.strip().lower().replace(" ", "_")
    return re.sub(r"_+", "_", s).strip("_")


def split_index(s):
    """Akira1 -> akira_1.  Fallback only: Crypt888 must stay Crypt888."""
    return re.sub(r"(?<=[a-z])(\d+)$", r"_\1", s)


def compact(s):
    return s.replace("_", "")


def load_samples(path=CSV):
    raw = open(path, encoding="utf-8-sig").read().lstrip("\ufeff")
    rows = list(csv.reader(raw.splitlines()))
    hdr = [h.strip().lstrip("\ufeff") for h in rows[0]]
    recs = [dict(zip(hdr, r + [""] * (len(hdr) - len(r)))) for r in rows[1:]]
    fam = ""
    for r in recs:
        if r["Family"].strip():
            fam = r["Family"].strip()
        r["_fam"] = fam
    return recs


def build(ext=EXT):
    if not ext:
        raise SystemExit(
            "the extracted traces are not part of this artifact; set "
            "RANSACK_EXTRACTED to a directory of per-trace .json files to "
            "reproduce this join")
    if not os.path.isdir(ext):
        raise SystemExit("RANSACK_EXTRACTED does not name a directory: %s" % ext)
    recs = load_samples()
    index = collections.defaultdict(list)
    for r in recs:
        s = r["sample"].strip()
        m = re.match(r"^(.*?)\s*\(([^)]*)\)\s*$", s)
        stem, arches = (m.group(1).strip(), [a.strip() for a in m.group(2).split(",")]) \
            if m else (s, [""])
        r["_stem"], r["_arches"] = stem, arches
        for a in arches:
            n = norm(stem)
            for key in {n, compact(n)}:
                index[(key, a.lower())].append(r)
                if key.endswith("_1"):
                    index[(key[:-2], a.lower())].append(r)
                    index[(compact(key[:-2]), a.lower())].append(r)

    trace2rec, unjoined, ambiguous = {}, [], []
    for p in glob.glob(os.path.join(ext, "*.json")):
        t = os.path.basename(p)[:-5]
        n = re.sub(r"_live$", "", re.sub(r"^trace_", "", t))
        m = re.search(r"_(32bit|64bit)$", n)
        stem, arch = (n[: m.start()], m.group(1)) if m else (n, "")
        ns = ALIAS.get(norm(stem), norm(stem))
        a = arch.lower()
        cand = (index.get((ns, a)) or index.get((compact(ns), a))
                or index.get((ns + "_1", a)) or index.get((split_index(ns), a))
                or index.get((split_index(ns) + "_1", a))
                or index.get((ns, "")) or index.get((split_index(ns), "")))
        if not cand:
            unjoined.append(t)
        else:
            uniq = {id(c): c for c in cand}
            if len(uniq) > 1:
                ambiguous.append(t)
            trace2rec[t] = cand[0]
    return trace2rec, recs, unjoined, ambiguous


if __name__ == "__main__":
    t2r, recs, unjoined, ambiguous = build()
    covered = {id(r) for r in t2r.values()}
    print(f"traces joined      : {len(t2r)}   unjoined: {len(unjoined)}   ambiguous: {len(ambiguous)}")
    print(f"csv rows covered   : {len(covered)} / {len(recs)}")

    # --- cross-check against the paper's execution_outcome ------------------
    by_outcome = collections.Counter(r["execution_outcome"] for r in recs)
    cov_outcome = collections.Counter(r["execution_outcome"] for r in recs if id(r) in covered)
    print("\nexecution_outcome      total   with-trace   without")
    for k, v in by_outcome.most_common():
        print(f"  {k:28} {v:5}   {cov_outcome[k]:5}   {v - cov_outcome[k]:5}")

    odd = [r for r in recs if id(r) in covered
           and r["execution_outcome"] != "Captured evidence"]
    print(f"\n*** traced but NOT 'Captured evidence': {len(odd)}")
    for r in odd:
        print(f"    {r['_fam']:20} {r['sample']:28} {r['execution_outcome']}")
