#!/usr/bin/env python3
"""Generate test-vectors/png-profile-vectors.json: presented images and the verdict each must get.

Every case claims to be the seal of (data "Hello", kind ""). A verifier decodes the presented file
under the verifiable-PNG profile of SPEC §6 and reports GENUINE (the profile accepts it and its
pixels are the genuine seal, after a faithful integer downscale), MISMATCH (the profile accepts it,
but the pixels are another image), or REJECTED (it is not a verifiable PNG, or it is the wrong size,
or its upscale blocks are not uniform). `rule` names the erratum that decides the case (E24: the
profile), or is null for behaviour every conforming verifier already has (E10, E12 and §6).

Usage:  python3 python/tools/gen_png_vectors.py
"""
import base64
import hashlib
import json
import pathlib
import struct
import sys
import zlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from inkan_standard.seal import CANVAS as N, seal_png, seal_rgb
from inkan_standard.seed import inkan_digest

OUT = pathlib.Path(__file__).resolve().parents[2] / "test-vectors" / "png-profile-vectors.json"
SIG = b"\x89PNG\r\n\x1a\n"
DATA, KIND = "Hello", ""
GENUINE = seal_rgb(inkan_digest(DATA, KIND), KIND)
OTHER = seal_rgb(inkan_digest("Hellp", KIND), KIND)


def chunk(t, b, crc=None):
    c = zlib.crc32(t + b) & 0xFFFFFFFF if crc is None else crc
    return struct.pack(">I", len(b)) + t + b + struct.pack(">I", c)


def ihdr(w, h, depth, ctype, comp=0, filt=0, inter=0):
    return chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, depth, ctype, comp, filt, inter))


def rows(px, w, encode, filters=(0,)):
    """Scanlines with a filter byte. Filter types cycle through `filters` row by row."""
    out, prev = bytearray(), None
    for y in range(len(px) // w):
        line = encode(px[y * w:(y + 1) * w])
        f = filters[y % len(filters)]
        bpp = max(1, len(line) // w)
        out.append(f)
        out += _filter(line, prev if prev is not None else bytes(len(line)), f, bpp)
        prev = line
    return bytes(out)


def _filter(line, prev, f, bpp):
    if f == 0:
        return line
    o = bytearray(len(line))
    for i in range(len(line)):
        a = line[i - bpp] if i >= bpp else 0
        b = prev[i]
        c = prev[i - bpp] if i >= bpp else 0
        if f == 1:
            p = a
        elif f == 2:
            p = b
        elif f == 3:
            p = (a + b) >> 1
        else:
            q = a + b - c
            pa, pb, pc = abs(q - a), abs(q - b), abs(q - c)
            p = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
        o[i] = (line[i] - p) & 0xFF
    return bytes(o)


def rgb_line(r):
    return b"".join(bytes(c) for c in r)


def indexed(px, w, pal, filters=(0,)):
    ix = {c: i for i, c in enumerate(pal)}
    return rows(px, w, lambda r: bytes(ix[c] for c in r), filters)


def png(*chunks):
    return SIG + b"".join(chunks)


def upscale(px, s):
    out = []
    for y in range(N * s):
        out.extend(px[(y // s) * N + (x // s)] for x in range(N * s))
    return out


def adam7(px):
    """Adam7-interlaced truecolour scanlines (filter 0), a valid interlaced PNG image stream."""
    out = bytearray()
    for x0, y0, dx, dy in ((0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4),
                           (1, 0, 2, 2), (0, 1, 1, 2)):
        for y in range(y0, N, dy):
            line = b"".join(bytes(px[y * N + x]) for x in range(x0, N, dx))
            if line:
                out.append(0); out += line
    return bytes(out)


def gif(frames):
    """A looping animated GIF (literal-only LZW, 9-bit codes); frame 1 genuine, frame 2 another seal."""
    allc = sorted(set(c for f in frames for c in f)); gpal = {c: i for i, c in enumerate(allc)}
    ct = b"".join(bytes(c) for c in allc) + b"\x00" * (3 * (256 - len(allc)))
    out = bytearray(b"GIF89a" + struct.pack("<HH", N, N) + bytes([0xF7, 0, 0]) + ct)
    out += b"\x21\xFF\x0BNETSCAPE2.0\x03\x01\x00\x00\x00"
    for f in frames:
        out += b"\x21\xF9\x04\x04" + struct.pack("<H", 100) + b"\x00\x00"
        out += b"\x2C" + struct.pack("<HHHH", 0, 0, N, N) + b"\x00"
        codes = []
        for k, c in enumerate(f):
            if k % 250 == 0:
                codes.append(256)
            codes.append(gpal[c])
        codes.append(257)
        bits = nb = 0; data = bytearray()
        for cd in codes:
            bits |= cd << nb; nb += 9
            while nb >= 8:
                data.append(bits & 0xFF); bits >>= 8; nb -= 8
        if nb:
            data.append(bits & 0xFF)
        out.append(8)
        for j in range(0, len(data), 255):
            blk = data[j:j + 255]; out.append(len(blk)); out += blk
        out.append(0)
    out.append(0x3B)
    return bytes(out)


def main():
    canon = seal_png(inkan_digest(DATA, KIND), KIND)
    tagged = seal_png(inkan_digest(DATA, KIND), KIND, tag=True)
    pal = sorted(set(GENUINE))
    plte = chunk(b"PLTE", b"".join(bytes(c) for c in pal))
    rev = pal[::-1]
    plte_rev = chunk(b"PLTE", b"".join(bytes(c) for c in rev))
    idat = indexed(GENUINE, N, pal)
    z = zlib.compress(idat, 9)
    tc = rows(GENUINE, N, rgb_line)
    after_ihdr = 8 + 25                                   # offset just past IHDR

    def insert(p, extra, at=after_ihdr):
        return p[:at] + extra + p[at:]

    text = (chunk(b"tEXt", b"Comment\x00re-encoded") + chunk(b"zTXt", b"Note\x00\x00" + zlib.compress(b"x"))
            + chunk(b"pHYs", struct.pack(">IIB", 2835, 2835, 1))
            + chunk(b"tIME", struct.pack(">HBBBBB", 2026, 10, 10, 12, 0, 0)))
    ex = (b"MM\x00\x2a\x00\x00\x00\x08" + struct.pack(">H", 1)
          + struct.pack(">HHIHH", 0x0112, 3, 1, 6, 0) + struct.pack(">I", 0))
    tampered = upscale(GENUINE, 2)
    for y in range(0, 2 * N, 2):                           # second pixel of every block from OTHER
        for x in range(0, 2 * N, 2):
            tampered[y * 2 * N + x + 1] = OTHER[(y // 2) * N + x // 2]
    bad_ix = bytearray(idat); bad_ix[1] = len(pal)          # first pixel indexes past the palette

    cases = [
        # accepted re-encodings
        ("canonical", "GENUINE", None, canon),
        ("tagged", "GENUINE", None, tagged),
        ("truecolour", "GENUINE", None, png(ihdr(N, N, 8, 2), chunk(b"IDAT", zlib.compress(tc, 9)), chunk(b"IEND", b""))),
        ("indexed-reversed-palette-all-filters", "GENUINE", None,
         png(ihdr(N, N, 8, 3), plte_rev, chunk(b"IDAT", zlib.compress(indexed(GENUINE, N, rev, (0, 1, 2, 3, 4)), 6)), chunk(b"IEND", b""))),
        ("truecolour-all-filters", "GENUINE", None,
         png(ihdr(N, N, 8, 2), chunk(b"IDAT", zlib.compress(rows(GENUINE, N, rgb_line, (4, 3, 2, 1, 0)), 1)), chunk(b"IEND", b""))),
        ("idat-split-in-three", "GENUINE", None,
         png(ihdr(N, N, 8, 3), plte, chunk(b"IDAT", z[:7]), chunk(b"IDAT", z[7:100]), chunk(b"IDAT", z[100:]), chunk(b"IEND", b""))),
        ("benign-metadata", "GENUINE", None, insert(canon, text)),
        ("suggested-palette-in-truecolour", "GENUINE", None,
         png(ihdr(N, N, 8, 2), plte, chunk(b"IDAT", zlib.compress(tc, 9)), chunk(b"IEND", b""))),
        ("upscale-2x", "GENUINE", None, png(ihdr(2 * N, 2 * N, 8, 2), chunk(b"IDAT", zlib.compress(rows(upscale(GENUINE, 2), 2 * N, rgb_line), 9)), chunk(b"IEND", b""))),
        # a valid image of another seal
        ("another-seal", "MISMATCH", None, seal_png(inkan_digest("Hellp", KIND), KIND)),
        # rejected by rules every verifier already has
        ("trns", "REJECTED", None, insert(canon, chunk(b"tRNS", b"\x00"), canon.index(b"IDAT") - 4)),
        ("gama", "REJECTED", None, insert(canon, chunk(b"gAMA", struct.pack(">I", 100000)))),
        ("actl-animation", "REJECTED", None, insert(canon, chunk(b"acTL", struct.pack(">II", 1, 0)))),
        ("rgba", "REJECTED", None, png(ihdr(N, N, 8, 6), chunk(b"IDAT", zlib.compress(rows(GENUINE, N, lambda r: b"".join(bytes(c) + b"\xff" for c in r)), 9)), chunk(b"IEND", b""))),
        ("rgb-16-bit", "REJECTED", None, png(ihdr(N, N, 16, 2), chunk(b"IDAT", zlib.compress(rows(GENUINE, N, lambda r: b"".join(struct.pack(">HHH", *(v * 257 for v in c)) for c in r)), 9)), chunk(b"IEND", b""))),
        ("indexed-4-bit", "REJECTED", None, png(ihdr(N, N, 4, 3), plte_rev, chunk(b"IDAT", zlib.compress(rows(GENUINE, N, lambda r: bytes((rev.index(r[i]) << 4) | rev.index(r[i + 1]) for i in range(0, N, 2))), 9)), chunk(b"IEND", b""))),
        ("interlaced", "REJECTED", None, png(ihdr(N, N, 8, 2, inter=1), chunk(b"IDAT", zlib.compress(adam7(GENUINE), 9)), chunk(b"IEND", b""))),
        ("animated-gif", "REJECTED", None, gif([GENUINE, OTHER])),
        ("upscale-blocks-not-uniform", "REJECTED", None, png(ihdr(2 * N, 2 * N, 8, 2), chunk(b"IDAT", zlib.compress(rows(tampered, 2 * N, rgb_line), 9)), chunk(b"IEND", b""))),
        ("wrong-size", "REJECTED", None,
         png(ihdr(N + 1, N + 1, 8, 2), chunk(b"IDAT", zlib.compress(bytes((N + 1) * (1 + 3 * (N + 1))), 9)), chunk(b"IEND", b""))),
        # rejected by the verifiable-PNG profile (E24)
        ("cicp-colour-space", "REJECTED", "E24", insert(canon, chunk(b"cICP", bytes([9, 16, 0, 1])))),
        ("exif-orientation", "REJECTED", "E24", insert(canon, chunk(b"eXIf", ex))),
        ("unknown-ancillary-chunk", "REJECTED", "E24", insert(canon, chunk(b"prVt", b"x"))),
        ("unknown-critical-chunk", "REJECTED", "E24", insert(canon, chunk(b"ABCD", b"x"))),
        ("bad-plte-crc", "REJECTED", "E24", png(ihdr(N, N, 8, 3), chunk(b"PLTE", plte[8:-4], crc=1), chunk(b"IDAT", z), chunk(b"IEND", b""))),
        ("bad-idat-crc", "REJECTED", "E24", png(ihdr(N, N, 8, 3), plte, chunk(b"IDAT", z, crc=0), chunk(b"IEND", b""))),
        ("no-iend", "REJECTED", "E24", canon[:-12]),
        ("bytes-after-iend", "REJECTED", "E24", canon + b"trailing"),
        ("bytes-after-zlib-stream", "REJECTED", "E24", png(ihdr(N, N, 8, 3), plte, chunk(b"IDAT", z + b"junk"), chunk(b"IEND", b""))),
        ("ihdr-compression-method-1", "REJECTED", "E24", png(ihdr(N, N, 8, 3, comp=1), plte, chunk(b"IDAT", z), chunk(b"IEND", b""))),
        ("ihdr-filter-method-1", "REJECTED", "E24", png(ihdr(N, N, 8, 3, filt=1), plte, chunk(b"IDAT", z), chunk(b"IEND", b""))),
        ("palette-index-out-of-range", "REJECTED", "E24", png(ihdr(N, N, 8, 3), plte, chunk(b"IDAT", zlib.compress(bytes(bad_ix), 9)), chunk(b"IEND", b""))),
        ("idat-before-plte", "REJECTED", "E24", png(ihdr(N, N, 8, 3), chunk(b"IDAT", z), plte, chunk(b"IEND", b""))),
        ("indexed-without-plte", "REJECTED", "E24", png(ihdr(N, N, 8, 3), chunk(b"IDAT", z), chunk(b"IEND", b""))),
        ("two-ihdr", "REJECTED", "E24", png(ihdr(N, N, 8, 3), ihdr(N, N, 8, 3), plte, chunk(b"IDAT", z), chunk(b"IEND", b""))),
    ]
    doc = {
        "comment": ("Presented images (SPEC 6, E24). Every case claims to be the seal of data "
                    "'Hello', kind ''. png_base64 is the presented file. GENUINE: a verifiable PNG "
                    "whose pixels are the genuine seal; MISMATCH: a verifiable PNG of other pixels; "
                    "REJECTED: not a verifiable PNG, the wrong size, or non-uniform upscale blocks. "
                    "'rule' names the erratum that decides the case, or is null for behaviour every "
                    "conforming verifier already has."),
        "data_utf8": DATA,
        "kind": KIND,
        "genuine_rgb_sha256": hashlib.sha256(bytes(c for p in GENUINE for c in p)).hexdigest(),
        "cases": [{"name": n, "expect": e, "rule": r, "png_base64": base64.b64encode(b).decode()}
                  for n, e, r, b in cases],
    }
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    print(f"wrote {OUT}: {len(cases)} cases, {OUT.stat().st_size} bytes")


if __name__ == "__main__":
    sys.exit(main())
