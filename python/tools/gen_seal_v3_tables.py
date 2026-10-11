#!/usr/bin/env python3
"""Write the Seal v3 tables as the published data file test-vectors/seal-v3-tables.json.

SPEC §3.0 pins this file's SHA-256. The file is the CANONICAL ENCODING of the frozen tables, so any
implementation can rebuild the exact bytes from its own copy of the tables and compare digests:

  * a single JSON object whose members are the nine tables plus the scalar constants of §3, named
    exactly as in the reference source;
  * object members sorted by key (code point order), no insignificant whitespace (separators ","
    and ":"), integers in shortest decimal form, every string pure ASCII and written without
    escapes, the whole followed by one line feed (0x0A).

Python: json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\\n".

Usage:  python3 python/tools/gen_seal_v3_tables.py            # write the file
        python3 python/tools/gen_seal_v3_tables.py --check    # exit 1 if the file differs
"""
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from inkan_standard import seal, seal_tables as T

OUT = pathlib.Path(__file__).resolve().parents[2] / "test-vectors" / "seal-v3-tables.json"


def tables_doc() -> dict:
    return {
        "FORMAT": "inkan-seal-v3-tables",
        "SEAL_VERSION": seal.SEAL_VERSION,
        "CANVAS": T.CANVAS,
        "STREAM_DOMAIN_HEX": seal._STREAM_DOMAIN.hex(),
        "KIND_DOMAIN_HEX": seal._KIND_DOMAIN.hex(),
        "GOLAY_G": seal._GOLAY_G,
        "TIER_CELLS": dict(T.TIER_CELLS),
        "KMAX": {str(c): k for c, k in T.KMAX.items()},
        "ORBIT_REPS": list(T.ORBIT_REPS),
        "KINDS": {name: list(entry) for name, entry in T.KINDS.items()},
        "PALETTE": [[list(rgb) for rgb in cls] for cls in T.PALETTE],
        "SELECT_WEIGHTS": list(T.SELECT_WEIGHTS),
        "CORE_PATTERNS": list(T.CORE_PATTERNS),
        "REGION_RLE": {key: "".join(parts) for key, parts in T.REGION_RLE.items()},
    }


def canonical(doc: dict) -> bytes:
    text = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if "\\" in text:
        raise SystemExit("FATAL: a table string needs an escape; the canonical form forbids that")
    return text.encode("ascii") + b"\n"


def main(argv) -> int:
    data = canonical(tables_doc())
    digest = hashlib.sha256(data).hexdigest()
    if "--check" in argv:
        ok = OUT.is_file() and OUT.read_bytes() == data
        print(("OK   " if ok else "FAIL ") + f"{OUT.name} sha256 {digest}")
        return 0 if ok else 1
    OUT.write_bytes(data)
    print(f"wrote {OUT} ({len(data)} bytes) sha256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
