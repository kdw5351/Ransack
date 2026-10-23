"""Aggregate the PinTool's io_events.jsonl per-loop and per-API.

Each event row is shaped:
    {"event":"io_api","thread_id":...,"api":"NtCreateFile",
     "dll":"ntdll.dll","group":"file_io","kind":"out",
     "loop_id":31,"loop_header":"...","loop_backedge":"...",
     "args":["0x...","0x...","0x...","0x..."]}

`args` are raw register values; the new PinTool does not dereference
them, so this module never tries to interpret pointers. The buckets here
are what we *can* trust.
"""
from __future__ import annotations

from collections import Counter, defaultdict


def summarize(io_events: list[dict]) -> dict:
    """Cross-loop totals + per-loop per-group counts.

    Returns:
        {
          "total_events": N,
          "by_group":     {file_io: ..., dir_io: ..., mmap_io: ..., handle_io: ...},
          "by_kind":      {in: ..., out: ...},
          "by_api":       {"NtCreateFile": ..., ...},
          "by_dll":       {"ntdll.dll": ..., ...},
          # sync docstring to actual emission - per_loop entries also include by_kind and by_dll
          "per_loop":     {loop_id: {"total": N,
                                     "by_group": {...},
                                     "by_api":   {...},
                                     "by_kind":  {...},
                                     "by_dll":   {...}}},
          "orphan_count": N        (events with loop_id == null)
        }
    """
    by_group: Counter = Counter()
    by_kind:  Counter = Counter()
    by_api:   Counter = Counter()
    by_dll:   Counter = Counter()
    per_loop: dict = defaultdict(lambda: {
        "total": 0,
        "by_group": Counter(),
        "by_api":   Counter(),
        "by_kind":  Counter(),
        "by_dll":   Counter(),
    })
    orphan = 0

    # track orphan breakdown so consumers can reconstruct
    # the invariant sum(per_loop totals) + orphan == total_events, and so the
    # per-group/kind/api/dll cross-loop totals remain decomposable.
    orphan_by_group: Counter = Counter()
    orphan_by_kind:  Counter = Counter()
    orphan_by_api:   Counter = Counter()
    orphan_by_dll:   Counter = Counter()

    for ev in io_events:
        grp  = ev.get("group") or "?"
        kind = ev.get("kind")  or "?"
        api  = ev.get("api")   or "?"
        dll  = ev.get("dll")   or "?"
        by_group[grp] += 1
        by_kind[kind] += 1
        by_api[api]   += 1
        by_dll[dll]   += 1

        lid = ev.get("loop_id")
        if lid is None:
            orphan += 1
            orphan_by_group[grp] += 1
            orphan_by_kind[kind] += 1
            orphan_by_api[api]   += 1
            orphan_by_dll[dll]   += 1
            continue
        slot = per_loop[lid]
        slot["total"] += 1
        slot["by_group"][grp] += 1
        slot["by_api"][api]   += 1
        slot["by_kind"][kind] += 1
        slot["by_dll"][dll]   += 1

    # Materialize Counters into plain dicts so the output is JSON-safe.
    return {
        "total_events": len(io_events),
        "by_group":     dict(by_group.most_common()),
        "by_kind":      dict(by_kind.most_common()),
        "by_api":       dict(by_api.most_common()),
        "by_dll":       dict(by_dll.most_common()),
        "per_loop": {
            lid: {
                "total":    slot["total"],
                "by_group": dict(slot["by_group"].most_common()),
                "by_api":   dict(slot["by_api"].most_common()),
                "by_kind":  dict(slot["by_kind"].most_common()),
                "by_dll":   dict(slot["by_dll"].most_common()),
            }
            for lid, slot in per_loop.items()
        },
        "orphan_count": orphan,
        # expose orphan breakdown so consumers can verify
        # by_group/by_kind/by_api/by_dll == sum(per_loop[*]) + orphan_breakdown.
        "orphan_breakdown": {
            "by_group": dict(orphan_by_group.most_common()),
            "by_kind":  dict(orphan_by_kind.most_common()),
            "by_api":   dict(orphan_by_api.most_common()),
            "by_dll":   dict(orphan_by_dll.most_common()),
        },
    }


