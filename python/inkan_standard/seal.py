# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 RexStarBSV
# Inkan verification path (see LICENSE-VERIFY and NOTICE). Repository default licence: BSL 1.1.
"""
inkan_standard.seal -- Inkan Seal v3 (ISv3), the visual seal engine. Original work.

A visual hash used as a trust signal has one job: **a human must notice when it
changes.** ISv3 makes perceptual separation a property of the construction:

  * STRUCTURE IS CODED. Interior cells hold 2 bits each, fed by bit-interleaved
    extended Golay [24,12,8] blocks (cell profiles 24/48/72). Any two distinct
    seals differ in at least 8 cells: popcount(A|B) >= max(|A|,|B|) >= 8. Verified
    in tests, not asserted.

  * SYMMETRY IS THE KIND, AND COSTS NOTHING. Each kind renders with C_k rotational
    symmetry (k = 1..7). The free-cell count is fixed per profile; only the
    replication varies, so every kind carries identical entropy and higher symmetry
    is pure visual amplification. (cells, k) is a function of the kind -- never a
    user knob -- because one digest must render one seal, everywhere, forever.

  * AVALANCHE COMES FROM A PRF. Every field is drawn from a domain-separated
    SHA-256 stream; flipping one input bit re-randomises everything.

  * COLOUR IS A FIELD, NOT A DECORATION. 32 classes x 5 roles, separated primarily
    by lightness (the only channel dichromats retain), selected under Brettel-
    Vienot-Mollon CVD simulation and sRGB gamut fitting. Selection is WEIGHTED
    (SELECT_WEIGHTS) so classes resembling disfavoured third-party marks appear
    rarely rather than never. The core is constant-weight (2 of 4 cells inked):
    never uniform, and the core colour always appears.

No floating point appears below: palette and region maps are precomputed integer
tables (seal_tables.py), so the Python, JS and Kotlin ports agree byte-for-byte by
construction rather than by luck.

Provenance: ISv3 shares no code, structure, or output with LifeHash. It is an
original design. The comparative measurements supporting that claim are retained
with the project's design records and are available on request.
"""
import base64
from hashlib import sha256

from .seal_tables import (CANVAS, CELL_PROFILES, CORE_PATTERNS, KINDS, KMAX,
                          ORBIT_REPS, PALETTE, REGION_RLE, SELECT_WEIGHTS, TIER_CELLS)
from .seed import _encode_utf8, reject_unassigned

__all__ = ["seal_rgb", "seal_rgb_from_fields", "seal_png", "seal_fields", "resolve_kind",
           "golay24", "cells_from_words", "KINDS", "SEAL_VERSION"]

SEAL_VERSION = 3
_STREAM_DOMAIN = b"inkan/seal/v3"
_KIND_DOMAIN = b"inkan/kind/v1\x00"


def resolve_kind(kind):
    """Resolve any kind string to ``(cells, k, motif)``. Reserved kinds use their curated entry;
    every other string is derived deterministically, so the standard is open to ANY kind while a
    seal still renders identically on every device, for any non-reserved kind string.

    Derivation: the optional ``@t1|@t2|@t3`` suffix picks the tier (cells); ``k`` and the frame
    ``motif`` come from a domain-separated SHA-256 of the full kind string, so no registry is needed
    and third parties assign their own kinds and tiers freely.

    A kind holding a code point this interpreter's Unicode database leaves unassigned is rejected
    here as in the anchor (SPEC §4.2, E14), so no seal is ever drawn for a kind that has no anchor."""
    entry = KINDS.get(kind)
    if entry is not None:
        return entry
    reject_unassigned(kind, "kind")
    tier = "t2"
    for t in ("t1", "t2", "t3"):
        if kind.endswith("@" + t):
            tier = t
            break
    cells = TIER_CELLS[tier]
    kh = sha256(_KIND_DOMAIN + _encode_utf8(kind, "kind")).digest()        # E4: refuse, never substitute
    k = 1 + (kh[0] % KMAX[cells])
    motif = ORBIT_REPS[kh[1] % len(ORBIT_REPS)]
    return cells, k, motif

# Weighted palette draw table: class i appears SELECT_WEIGHTS[i] times. Expansion
# order is normative; every port must build the identical table.
_SELECT_TABLE = tuple(i for i, w in enumerate(SELECT_WEIGHTS) for _ in range(w))


# ------------------------------------------------------------- codes (integer only)
_GOLAY_G = 0xAE3   # x^11+x^9+x^7+x^6+x^5+x+1 -> cyclic [23,12,7]


def golay24(info12):
    """12 info bits -> 24-bit extended Golay codeword (parity bit in bit 0).
    Non-systematic; a bijection with minimum weight 8 is all the seal needs."""
    c = 0
    for b in range(12):
        if (info12 >> b) & 1:
            c ^= _GOLAY_G << b
    return (c << 1) | (bin(c).count("1") & 1)




# ------------------------------------------------------------- field extraction
class _Stream:
    """SHA-256 in counter mode: an endless, portable byte stream over the digest."""

    def __init__(self, digest):
        self._d = digest
        self._buf = b""
        self._ctr = 0

    def byte(self):
        if not self._buf:
            self._buf = sha256(self._d + _STREAM_DOMAIN + self._ctr.to_bytes(4, "big")).digest()
            self._ctr += 1
        b, self._buf = self._buf[0], self._buf[1:]
        return b


def _uniform(stream, n):
    """Rejection-sampled uniform value in [0, n). Unbiased -- a plain `byte % n`
    over-weights the low residues whenever n does not divide 256."""
    limit = 256 - (256 % n)
    while True:
        b = stream.byte()
        if b < limit:
            return b % n


def seal_fields(digest, kind=""):
    """Derive (cell_words, palette_index, core_pattern) from a 32-byte digest.

    Draw order is NORMATIVE; every port must consume the stream in exactly this
    sequence or the seals diverge:
      cells/12 words, each 2 bytes big-endian masked to 12 bits;
      then the palette class (rejection-sampled over the weighted table);
      then the core pattern (rejection-sampled over the 6 constant-weight patterns).
    """
    if len(digest) != 32:
        raise ValueError("digest must be 32 bytes")
    cells = resolve_kind(kind)[0]
    s = _Stream(digest)
    words = tuple((((s.byte() << 8) | s.byte()) & 0xFFF) for _ in range(cells // 12))
    palette_ix = _SELECT_TABLE[_uniform(s, len(_SELECT_TABLE))]
    core = CORE_PATTERNS[_uniform(s, len(CORE_PATTERNS))]
    return words, palette_ix, core


def cells_from_words(words, cells):
    """Info words -> per-cell 2-bit states, via the profile's code + interleave."""
    out = []
    for g in range(cells // 24):
        A, B = golay24(words[2 * g]), golay24(words[2 * g + 1])
        out += [(((B >> i) & 1) << 1) | ((A >> i) & 1) for i in range(24)]
    return out


# ------------------------------------------------------------- region maps
_REGION_CACHE = {}


def _region(cells, k):
    key = f"{cells},{k}"
    reg = _REGION_CACHE.get(key)
    if reg is None:
        blob = base64.b64decode("".join(REGION_RLE[key]))
        reg = []
        for i in range(0, len(blob), 3):
            reg.extend([blob[i]] * (blob[i + 1] | (blob[i + 2] << 8)))
        if len(reg) != CANVAS * CANVAS:
            raise ValueError(f"corrupt region table {key}")
        _REGION_CACHE[key] = reg
    return reg


# ------------------------------------------------------------- render
def seal_rgb_from_fields(words, palette_ix, core_pattern, kind=""):
    """Render directly from fields. Exposed so conformance tests can CONSTRUCT the
    worst case (minimum-weight codeword differences) instead of hoping to sample it."""
    cells, k, motif = resolve_kind(kind)
    cl = cells_from_words(words, cells)
    ground, a1, a2, a3, core_c = PALETTE[palette_ix]
    petal = (ground, a1, a2, a3)
    out = []
    for r in _region(cells, k):
        if r < cells:
            out.append(petal[cl[r]])
        elif r < 200:
            out.append(core_c if (core_pattern >> (r - 100)) & 1 else ground)
        elif r < 255:
            out.append(a1 if (motif >> (r - 200)) & 1 else ground)
        else:
            out.append(ground)
    return out


def seal_rgb(digest, kind=""):
    """Render a 32-byte digest to CANVAS*CANVAS (r, g, b) tuples. At most 5 colours."""
    return seal_rgb_from_fields(*seal_fields(digest, kind), kind=kind)


# ------------------------------------------------------------- PNG (indexed)
def seal_png(digest, kind="", scale=1, tag=False):
    """Render the seal as a PNG.

    Default (``tag=False``) is the CANONICAL seal: 8-bit indexed, exactly IHDR/PLTE/IDAT/IEND, no
    ancillary chunks. The cross-language invariant is the DECODED RGB pixel content (SPEC §5) —
    deflate output may differ between zlib builds, so nothing (vectors, comparison protocol, or
    any on-chain record) may ever pin compressed PNG bytes; pin the anchor or rgb_sha256.
    `scale` is integer nearest-neighbour.

    ``tag=True`` additionally embeds the Inkan's full 64-hex code (the glyph digest) and its kind as
    ``iTXt`` metadata, producing a **self-describing** artifact for distribution. The pixels are
    identical, so a tagged image compares equal to a canonical one at the RGB level. The embedded
    code is an UNTRUSTED HINT — it is attacker-controllable, so a verifier must recompute and compare
    pixels, treating the tag only as a cross-check (see ``inkan_standard.verify``)."""
    import struct
    import zlib

    px = seal_rgb(digest, kind)
    pal = sorted(set(px))
    ix = {c: i for i, c in enumerate(pal)}
    w = h = CANVAS * scale

    raw = bytearray()
    for y in range(h):
        raw.append(0)                                    # filter: none
        raw.extend(ix[px[(y // scale) * CANVAS + (x // scale)]] for x in range(w))

    def chunk(name, data):
        c = name + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    def itxt(keyword, text):
        # keyword \0 comp_flag(0) comp_method(0) lang(\0) transkeyword(\0) UTF-8 text
        body = keyword.encode("latin-1") + b"\x00\x00\x00\x00\x00" + text.encode("utf-8")
        return chunk(b"iTXt", body)

    meta = b""
    if tag:
        from .seed import CODE_PREFIX
        meta = itxt("inkan-code", CODE_PREFIX + digest.hex()) + itxt("inkan-kind", kind)

    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 3, 0, 0, 0))
            + chunk(b"PLTE", b"".join(bytes(c) for c in pal))
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
            + meta
            + chunk(b"IEND", b""))
