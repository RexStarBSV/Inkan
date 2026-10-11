#!/usr/bin/env python3
"""Generate test-vectors/seal-v3-coverage-vectors.json: Seal v3 vectors that reach every table entry.

The sampled vectors in seal-v3-vectors.json never touch region maps 24,2 and 24,3, palette class 21,
ten of the fourteen open-kind frame motifs, or the second block of the field stream, so an engine
with one of those entries wrong passed every test. These vectors close that gap:

  * coverage: one open kind for every (region map, frame motif) pair -- all 13 maps x all 14
    ORBIT_REPS values -- each with a digest chosen so that, together, the set draws every one of
    the 32 palette classes and all 6 core patterns;
  * second_block: two digests whose field draws read past the first 32-byte stream block (one in
    the palette draw, one in the core draw), which ordinary inputs do about once in two billion.

Pixels are pinned by rgb_sha256 (SPEC §3.7); compressed PNG sizes are deliberately not recorded.
Every port must reproduce these exactly; they test nothing a conforming engine does not already do.

Usage:  python3 python/tools/gen_seal_v3_coverage.py
"""
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from inkan_standard import seal, seal_tables as T

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "test-vectors" / "seal-v3-coverage-vectors.json"
TIER_OF = {72: "t1", 48: "t2", 24: "t3"}

# Found by exhaustive search over d = 24 zero bytes || u64be(n), 72-cell kinds (six info words).
SECOND_BLOCK = [(54502426, "core"), (250418282, "palette")]


def entry(kind, digest):
    words, pix, core = seal.seal_fields(digest, kind)
    rgb = bytes(c for px in seal.seal_rgb_from_fields(words, pix, core, kind) for c in px)
    return {"kind": kind, "resolve": list(seal.resolve_kind(kind)), "digest_hex": digest.hex(),
            "words": list(words), "palette_ix": pix, "core_pattern": core,
            "rgb_sha256": hashlib.sha256(rgb).hexdigest()}


def stream_bytes_read(digest, cells):
    """How many stream bytes the three draws consume (more than 32 means the second block)."""
    s = seal._Stream(digest)
    for _ in range(cells // 12):
        s.byte(); s.byte()
    seal._uniform(s, len(seal._SELECT_TABLE))
    seal._uniform(s, len(T.CORE_PATTERNS))
    return 32 * s._ctr - len(s._buf)


def main():
    want = [(cells, k, m) for cells in (24, 48, 72) for k in range(1, T.KMAX[cells] + 1)
            for m in T.ORBIT_REPS]
    found, n = {}, 0
    while len(found) < len(want):
        for cells in (24, 48, 72):
            name = f"cover:{n}@{TIER_OF[cells]}"
            r = seal.resolve_kind(name)
            if r not in found:
                found[r] = name
        n += 1
    seen_pal, seen_core, coverage = set(), set(), []
    for key in want:
        kind = found[key]
        chosen = None
        for j in range(20000):
            d = hashlib.sha256(f"inkan/v3/cover/{kind}/{j}".encode()).digest()
            _, pix, core = seal.seal_fields(d, kind)
            if pix not in seen_pal or (len(seen_pal) == 32 and core not in seen_core):
                chosen = d
                break
        if chosen is None:
            chosen = hashlib.sha256(f"inkan/v3/cover/{kind}/0".encode()).digest()
        e = entry(kind, chosen)
        seen_pal.add(e["palette_ix"]); seen_core.add(e["core_pattern"])
        coverage.append(e)
    maps = {f"{c},{k}" for c, k, _ in (e["resolve"] for e in coverage)}
    motifs = {e["resolve"][2] for e in coverage}
    assert maps == set(T.REGION_RLE), maps
    assert motifs == set(T.ORBIT_REPS)
    assert seen_pal == set(range(len(T.PALETTE))), sorted(set(range(32)) - seen_pal)
    assert seen_core == set(T.CORE_PATTERNS)

    second = []
    for n, draw in SECOND_BLOCK:
        d = bytes(24) + n.to_bytes(8, "big")
        e = entry("address", d)
        e["stream_bytes_read"] = stream_bytes_read(d, 72)
        e["second_block_draw"] = draw
        assert e["stream_bytes_read"] > 32
        second.append(e)

    tables = ROOT / "test-vectors" / "seal-v3-tables.json"
    doc = {
        "comment": ("Seal v3 coverage vectors (SPEC 3). 'coverage' reaches all 13 region maps x all "
                    "14 open-kind frame motifs and, together, all 32 palette classes and all 6 core "
                    "patterns; 'second_block' reads past the first 32-byte field-stream block. "
                    "Pixels are pinned by rgb_sha256 over the RGB888 bytes in row-major order."),
        "seal_version": seal.SEAL_VERSION,
        "tables_sha256": hashlib.sha256(tables.read_bytes()).hexdigest(),
        "coverage": coverage,
        "second_block": second,
    }
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    print(f"wrote {OUT}: {len(coverage)} coverage + {len(second)} second-block vectors "
          f"({len(maps)} maps, {len(motifs)} motifs, {len(seen_pal)} classes, {len(seen_core)} cores)")


if __name__ == "__main__":
    main()
