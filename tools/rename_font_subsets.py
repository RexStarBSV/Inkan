#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# SPDX-FileCopyrightText: 2026 RexStarBSV
"""Rename the IBM Plex Sans subsets the web verifier embeds to "Inkan Sans", as the OFL requires.

WHY. IBM distributes IBM Plex under the SIL Open Font License 1.1 with the header 'Copyright 2017 IBM
Corp. with Reserved Font Name "Plex"'. A subset is a Modified Version, and OFL section 3 forbids a
Modified Version to use a Reserved Font Name as its primary name. The subsets embedded in the verifier
page still called themselves "IBM Plex Sans" in their family, full and PostScript names, and the
page, NOTICE and LICENSING.md all asserted that no Reserved Font Name existed. It did. This tool makes
the font files true; the prose was corrected in the same commit.

WHAT IT CHANGES, AND NOTHING ELSE. Every glyph, metric and layout table is copied byte for byte. Two
tables change:

  * `name` is rebuilt from the fixed table below. IBM's copyright notice (nameID 0) and version
    (nameID 5) are kept verbatim and are CHECKED against the input, so this cannot be pointed at some
    other font by mistake. The licence (nameID 13) and licence URL (nameID 14), which the original
    subsetting stripped, are restored, because OFL condition 2 asks for the licence to travel with the
    font. nameID 10 says what was modified and that IBM does not endorse it.
  * `OS/2.achVendID` becomes "NONE", so the modified font does not identify itself as IBM's product.

The sfnt is then re-laid in the input's own physical table order with fresh table checksums and
`head.checkSumAdjustment`. The output is a pure function of the input's non-name tables, so running
this on the original subsets and on its own output gives the same bytes: the rebuild is deterministic
and idempotent.

    python3 tools/rename_font_subsets.py --from DIR --to DIR    # reads IBMPlexSans-<W>.subset.ttf
                                                                # or InkanSans-<W>.subset.ttf
"""
from __future__ import annotations

import argparse
import pathlib
import struct
import sys

COPYRIGHT = "Copyright 2018 IBM Corp. All rights reserved."
VERSION = "Version 3.005"
LICENCE = ("This Font Software is licensed under the SIL Open Font License, Version 1.1. "
           "This license is available with a FAQ at: http://scripts.sil.org/OFL")
LICENCE_URL = "http://scripts.sil.org/OFL"
DESCRIPTION = ("Inkan Sans is a Modified Version of IBM Plex Sans 3.005 under the SIL Open Font "
               "License 1.1: subset to the characters the Inkan web verifier uses, and renamed "
               "because \"Plex\" is a Reserved Font Name. It is not endorsed by IBM.")
VENDOR = b"NONE"

# weight -> (family nameID 1, subfamily nameID 2, full nameID 4, PostScript nameID 6). The family and
# subfamily split mirrors IBM's own (SemiBold is its own "SmBld" family), so the three faces resolve
# exactly as the originals did.
FACES = {
    "Regular":  ("Inkan Sans",       "Regular", "Inkan Sans",       "InkanSans-Regular"),
    "SemiBold": ("Inkan Sans SmBld", "Regular", "Inkan Sans SmBld", "InkanSans-SmBld"),
    "Bold":     ("Inkan Sans",       "Bold",    "Inkan Sans Bold",  "InkanSans-Bold"),
}
INPUT_NAMES = ("IBMPlexSans-%s.subset.ttf", "InkanSans-%s.subset.ttf")
OUTPUT_NAME = "InkanSans-%s.subset.ttf"


def _checksum(data: bytes) -> int:
    data += b"\0" * (-len(data) % 4)
    return sum(struct.unpack(">%dI" % (len(data) // 4), data)) & 0xFFFFFFFF


def _tables(font: bytes) -> list[tuple[bytes, int, bytes]]:
    sfnt, count = struct.unpack(">IH", font[:6])
    if sfnt != 0x00010000:
        raise SystemExit("FATAL: not a TrueType sfnt (version %08x)" % sfnt)
    out = []
    for i in range(count):
        tag, _cs, off, ln = struct.unpack(">4sIII", font[12 + 16 * i:28 + 16 * i])
        out.append((tag, off, font[off:off + ln]))
    return out


def _read_names(name: bytes) -> dict[int, str]:
    _fmt, count, base = struct.unpack(">HHH", name[:6])
    got = {}
    for i in range(count):
        pid, eid, _lid, nid, ln, off = struct.unpack(">HHHHHH", name[6 + 12 * i:18 + 12 * i])
        raw = name[base + off:base + off + ln]
        if pid == 3 and eid == 1:
            got[nid] = raw.decode("utf-16-be")
    return got


def _build_names(records: dict[int, str]) -> bytes:
    heads, blob = [], b""
    for nid in sorted(records):
        s = records[nid].encode("utf-16-be")
        heads.append(struct.pack(">HHHHHH", 3, 1, 0x409, nid, len(s), len(blob)))
        blob += s
    return struct.pack(">HHH", 0, len(records), 6 + 12 * len(records)) + b"".join(heads) + blob


def rename(font: bytes, weight: str) -> bytes:
    family, sub, full, ps = FACES[weight]
    tables = _tables(font)
    by_tag = {t: d for t, _o, d in tables}
    old = _read_names(by_tag[b"name"])
    if old.get(0) != COPYRIGHT or old.get(5) != VERSION:
        raise SystemExit("FATAL: %s input carries copyright %r / version %r, not IBM Plex Sans 3.005's. "
                         "Refusing to relabel a font this tool was not written for."
                         % (weight, old.get(0), old.get(5)))
    names = {0: COPYRIGHT, 1: family, 2: sub, 3: "3.005;NONE;" + ps, 4: full, 5: VERSION, 6: ps,
             10: DESCRIPTION, 13: LICENCE, 14: LICENCE_URL}
    new = dict(by_tag)
    new[b"name"] = _build_names(names)
    os2 = bytearray(by_tag[b"OS/2"])
    os2[58:62] = VENDOR
    new[b"OS/2"] = bytes(os2)
    head = bytearray(by_tag[b"head"])
    head[8:12] = b"\0\0\0\0"                      # checkSumAdjustment is computed over the result
    new[b"head"] = bytes(head)

    order = [t for t, _o, _d in sorted(tables, key=lambda x: x[1])]      # input's physical order
    dir_tags = [t for t, _o, _d in tables]                               # directory order (by tag)
    count = len(dir_tags)
    pos = 12 + 16 * count
    offsets, body = {}, b""
    for t in order:
        offsets[t] = pos + len(body)
        body += new[t] + b"\0" * (-len(new[t]) % 4)
    header = font[:12]
    directory = b"".join(struct.pack(">4sIII", t, _checksum(new[t]), offsets[t], len(new[t]))
                         for t in dir_tags)
    out = bytearray(header + directory + body)
    adj = (0xB1B0AFBA - _checksum(bytes(out))) & 0xFFFFFFFF
    h = offsets[b"head"]
    out[h + 8:h + 12] = struct.pack(">I", adj)
    return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--from", dest="src", required=True)
    ap.add_argument("--to", dest="dst", required=True)
    a = ap.parse_args()
    src, dst = pathlib.Path(a.src), pathlib.Path(a.dst)
    dst.mkdir(parents=True, exist_ok=True)
    for weight in FACES:
        inp = next((src / (n % weight) for n in INPUT_NAMES if (src / (n % weight)).is_file()), None)
        if inp is None:
            raise SystemExit("FATAL: no %s subset in %s (looked for %s)"
                             % (weight, src, ", ".join(n % weight for n in INPUT_NAMES)))
        out = rename(inp.read_bytes(), weight)
        (dst / (OUTPUT_NAME % weight)).write_bytes(out)
        print("  %s -> %s (%d bytes)" % (inp.name, OUTPUT_NAME % weight, len(out)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
