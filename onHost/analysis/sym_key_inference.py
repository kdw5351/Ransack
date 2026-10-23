"""Rule-driven symmetric key algorithm inference.

Symmetric-key algorithm inference. When a captured
symmetric key has no explicit algorithm tag (e.g. it came from
`BCryptGenerateSymmetricKey` whose algorithm depends on the handle), the
rules in `sym_key_inference_rules.json` map (key_len_bytes, context)
to a concrete algorithm name + confidence + spec citation.

Rule format:
  {
    "if": {
      "key_len_bytes": 32,
      "key_len_bytes_in": [16, 32],
      "context": "bcrypt",
      "context_in": ["aes", "bcrypt"],
      "context_not_in": ["wrapped_key_sink_plaintext_binary"]
    },
    "infer": {"algorithm": "AES-256", "confidence": 0.9},
    "spec_citation": "..."
  }
"""
from __future__ import annotations

from typing import Optional

from .catalogs import Catalogs


def _matches(cond: dict, key_len_bytes: int, context: str, key_hex: str = "") -> bool:
    ctx_l = (context or "").lower()
    if "key_len_bytes" in cond and cond["key_len_bytes"] != key_len_bytes:
        return False
    if "key_len_bytes_in" in cond and key_len_bytes not in cond["key_len_bytes_in"]:
        return False
    if "context" in cond and cond["context"] not in ctx_l:
        return False
    if "context_in" in cond and not any(c in ctx_l for c in cond["context_in"]):
        return False
    if "context_not_in" in cond and any(c in ctx_l for c in cond["context_not_in"]):
        return False
    if "byte_match_any" in cond:
        # The rule requires a specific byte pattern to be present in the captured
        # key material (e.g. the AES Rcon sequence). Fail closed: without the key
        # bytes, or with no listed pattern present, the rule must NOT match on
        # length alone -- that is exactly the length-only false positive the gate
        # was added to prevent (see the rule's own note).
        kh = (key_hex or "").lower()
        if not kh or not any(str(p).lower() in kh for p in cond["byte_match_any"]):
            return False
    return True


def infer(catalogs: Catalogs, key_len_bytes: int,
          context: str = "", key_hex: str = "") -> tuple[Optional[str], float, Optional[str]]:
    """Returns (algorithm, confidence, spec_citation) or (None, 0.0, None)."""
    rules = catalogs.sym_key_inference or []
    for r in rules:
        if not _matches(r.get("if", {}) or {}, key_len_bytes, context, key_hex):
            continue
        inf = r.get("infer", {}) or {}
        return inf.get("algorithm"), float(inf.get("confidence", 0)), r.get("spec_citation")
    return None, 0.0, None


def annotate_sym_keys(catalogs: Catalogs, sym_keys: list[dict]) -> dict:
    """Walks the sym_keys list (from crypto_summary) and fills in algorithm
    via rule lookup when missing. Mutates entries in-place. Returns summary
    counts of inference outcomes.
    """
    n_total = len(sym_keys)
    n_with_algo_in = sum(1 for k in sym_keys if k.get("algorithm"))
    n_inferred = 0
    by_algo: dict[str, int] = {}
    for k in sym_keys:
        if k.get("algorithm"):
            continue
        klen = int(k.get("len") or 0)
        ctx = " ".join(filter(None, [k.get("api", ""), k.get("source", ""),
                                       k.get("kind", "")])).lower()
        algo, conf, cite = infer(catalogs, klen, context=ctx,
                                  key_hex=str(k.get("hex") or ""))
        if algo:
            k["algorithm"] = algo
            k["algorithm_source"] = "inferred"
            k["algorithm_confidence"] = conf
            k["algorithm_spec_citation"] = cite
            n_inferred += 1
            by_algo[algo] = by_algo.get(algo, 0) + 1
    return {
        "total_keys": n_total,
        "with_algorithm_in": n_with_algo_in,
        "inferred": n_inferred,
        "by_inferred_algo": by_algo,
        "rules_loaded": len(catalogs.sym_key_inference or []),
    }
