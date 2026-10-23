from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


@dataclass
class Catalogs:
    crypto_constants: list[dict] = field(default_factory=list)
    sym_key_inference: list[dict] = field(default_factory=list)
    assets_dir: str = ""


def _read_json(path: str, default):
    if not os.path.isfile(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_catalogs(assets_dir: str) -> Catalogs:
    # Only the two catalogs consumed through this object are loaded here: the
    # magic-byte cipher-constant scanner (crypto_constants) and the symmetric-key
    # length-inference rules. The loop-pattern and DLL-role catalogs are read
    # directly from their file paths by loop_classifier, and the crypto-API /
    # file-I/O hook tables are consumed by the onVM pintool, not onHost.
    c = Catalogs(assets_dir=os.path.abspath(assets_dir))

    const_doc = _read_json(os.path.join(assets_dir, "crypto_constants.json"), {})
    c.crypto_constants = const_doc.get("constants") or []

    sym_doc = _read_json(os.path.join(assets_dir, "sym_key_inference_rules.json"), {})
    c.sym_key_inference = sym_doc.get("rules") or []

    return c

