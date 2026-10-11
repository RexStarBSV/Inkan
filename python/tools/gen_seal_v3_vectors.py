#!/usr/bin/env python3
"""Generate the language-agnostic Seal v3 conformance vectors.

Every port (JS, Kotlin) must reproduce these byte-for-byte. Two vector families:

  * sampled: per kind, 5 digests -> fields + PNG SHA-256. Catches any divergence in
    the stream, the draw order, the codes, the weighted palette table, the region
    maps, or the PNG writer.
  * constructed: per Golay profile, a minimum-weight codeword difference -- the two
    most similar seals the code can emit. A port must be able to CONSTRUCT the worst
    case, not hope to sample it.

Usage:  PYTHONPATH=python python3 python/tools/gen_seal_v3_vectors.py
"""
import hashlib, json, pathlib, sys

sys.path.insert(0, str(pathlib.Path(__file__).parents[1]))
from inkan_standard import seal

# Open kinds are included so every port must reproduce the DERIVATION (string -> cells,k,motif),
# not just the reserved table. Spans all three tiers, a namespace, no suffix, and non-ASCII.
OPEN_KINDS = ["acme:vault@t1", "acme:invoice@t3", "receipt", "myapp:thing", "café@t2"]
ALL_KINDS = sorted(seal.KINDS) + OPEN_KINDS

out = {"seal_version": seal.SEAL_VERSION, "stream_domain": "inkan/seal/v3",
       "canvas": 224, "kinds": {}, "open_kinds": OPEN_KINDS,
       "sampled": [], "constructed_worst_case": []}

for kind in ALL_KINDS:
    cells, k, motif = seal.resolve_kind(kind)
    out["kinds"][kind] = {"cells": cells, "k": k, "motif": motif}

for kind in ALL_KINDS:
    for i in range(5):
        digest = hashlib.sha256(f"inkan/v3/vec/{kind}/{i}".encode()).digest()
        words, pix, core = seal.seal_fields(digest, kind)
        png = seal.seal_png(digest, kind)
        rgb = bytes(c for px in seal.seal_rgb_from_fields(words, pix, core, kind) for c in px)
        out["sampled"].append({
            "kind": kind, "digest_hex": digest.hex(),
            "words": list(words), "palette_ix": pix, "core_pattern": core,
            "rgb_sha256": hashlib.sha256(rgb).hexdigest(),
            # png_sha256 deliberately NOT emitted: BRC-145 makes decoded RGB the
            # cross-language invariant, so pinning compressed bytes is a trap.
            "png_bytes": len(png),
        })

e8 = next(x for x in range(1, 4096) if bin(seal.golay24(x)).count("1") == 8)
for kind, cells in [("custom/24", 24), ("", 48), ("address", 72)]:
    digest = hashlib.sha256(f"inkan/v3/worst/{cells}".encode()).digest()
    words, pix, core = seal.seal_fields(digest, kind)
    words2 = (words[0] ^ e8,) + words[1:]
    c1 = seal.cells_from_words(words, cells)
    c2 = seal.cells_from_words(words2, cells)
    diff = sum(a != b for a, b in zip(c1, c2))
    assert diff == 8, diff
    h1 = hashlib.sha256(bytes(c for px in seal.seal_rgb_from_fields(words, pix, core, kind) for c in px)).hexdigest()
    h2 = hashlib.sha256(bytes(c for px in seal.seal_rgb_from_fields(words2, pix, core, kind) for c in px)).hexdigest()
    out["constructed_worst_case"].append({
        "kind": kind, "cells": cells, "digest_hex": digest.hex(),
        "min_weight_error_word": e8, "cells_differing": diff,
        "rgb_sha256_a": h1, "rgb_sha256_b": h2,
    })

path = pathlib.Path(__file__).parents[2] / "test-vectors" / "seal-v3-vectors.json"
path.write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
n = len(out["sampled"])
print(f"wrote {path}  ({n} sampled + {len(out['constructed_worst_case'])} constructed)")
