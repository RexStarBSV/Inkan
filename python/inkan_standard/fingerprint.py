# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 RexStarBSV
# Inkan verification path (see LICENSE-VERIFY and NOTICE). Repository default licence: BSL 1.1.
"""
inkan_standard.fingerprint — tamper-evidence fingerprints.

The cryptographic fingerprint of any bytes (a code build, an asset, a config) is:

    digest = SHA256( domain_prefix || payload )
    domain_prefix = b"<adopter>/inkan/v<version>\\x00"

The per-adopter `domain_prefix` namespaces each project so identical payloads yield DISTINCT
fingerprints across adopters, while the scheme stays universally verifiable. A one-byte change in
`payload` produces a completely different digest (avalanche).

Optionally render the digest as an **Inkan Seal v3** image — a human-memorable visual that
changes recognisably under tampering. Seal v3 is original work with no third-party dependency
(see `inkan_standard.seal`); the digest itself needs only the standard library. Ports MUST match the
reference RGB pixels (see ../test-vectors/seal-v3-vectors.json); the digest is the portable
cryptographic anchor.
"""
import hashlib
import struct
import zlib


def check_version(version) -> int:
    """A fingerprint version is a positive integer: 1, 2, 3, ... (SPEC §7, E22).

    Anything else is refused: zero, a negative number, a fraction, a string, a boolean (``True`` is
    an ``int`` in Python, and would otherwise pass as version 1). Version *n* is SHA-256 over this
    construction with ``dec(n)`` in the suffix, forever; a fingerprint over another hash is not a new
    version of this scheme. Before E22 any value was accepted, and a fraction was truncated here
    (1.5 gave the version-1 digest) while JavaScript wrote it out, so one input had two digests."""
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ValueError("fingerprint version must be a positive integer (1, 2, 3, ...), got %r "
                         "(SPEC §7 E22)" % (version,))
    return version


def check_adopter(adopter: str) -> str:
    """Refuse an adopter name the profile does not allow, before anything is hashed (SPEC §7, E6,
    E21), and return its NFC form.

    The profile is fixed by code-point ranges, so it does not move as Unicode assigns characters: the
    name is well-formed (E4), holds no code point this database leaves unassigned (E14), holds no
    control character (U+0000-U+001F, U+007F-U+009F; NUL included), and after NFC does not begin with
    ``nkan/``. The last rule closes the one cross-context parse: for a name of length 0x69 the length
    byte is ASCII ``i``, the preimage opens with the nine bytes of the glyph domain ``inkan/v1\\0``,
    and one digest would be both a fingerprint and an anchor."""
    import unicodedata
    from .seed import _encode_utf8, reject_unassigned
    reject_unassigned(adopter, "adopter name")                                  # E14 (+ type)
    for i, c in enumerate(adopter):
        cp = ord(c)
        if cp <= 0x1F or 0x7F <= cp <= 0x9F:
            raise ValueError("adopter name contains the control character U+%04X at position %d; an "
                             "adopter name MUST be printable (SPEC §7 E21)" % (cp, i))
    nfc = unicodedata.normalize("NFC", adopter)
    _encode_utf8(nfc, "adopter name")                                           # E4
    if nfc.startswith("nkan/"):
        raise ValueError("an adopter name MUST NOT begin with 'nkan/' (after NFC): with the length "
                         "byte it could spell the glyph domain 'inkan/v1\\0', making one digest both "
                         "a fingerprint and an anchor (SPEC §7 E6, E21)")
    return nfc


def domain_prefix(adopter: str, version: int = 1) -> bytes:
    """Per-adopter fingerprint domain: ``u8(len(adopter)) + adopter + "/inkan/v<version>\\0"``.

    The adopter is **length-prefixed** so the adopter/payload boundary is unambiguous — closing the
    same class of collision that the glyph seed had (an adopter name containing the domain structure
    could otherwise be confused with a longer adopter). Adopter names are NFC-normalised, ``<= 255``
    UTF-8 bytes, and must meet the profile `check_adopter` enforces; ``version`` must be a positive
    integer (`check_version`). Both are checked before anything is hashed."""
    version = check_version(version)
    a = check_adopter(adopter).encode("utf-8")
    if len(a) > 255:
        raise ValueError("adopter must be at most 255 UTF-8 bytes")
    return bytes([len(a)]) + a + ("/inkan/v%d\x00" % version).encode("ascii")


def fingerprint_digest(payload: bytes, adopter: str, version: int = 1) -> bytes:
    """SHA256(domain_prefix(adopter, version) || payload) — the 32-byte tamper fingerprint."""
    return hashlib.sha256(domain_prefix(adopter, version) + payload).digest()


def fingerprint_hex(payload: bytes, adopter: str, version: int = 1) -> str:
    return fingerprint_digest(payload, adopter, version).hex()


def digest_to_inkan_png(digest: bytes, scale: int = 8) -> bytes:
    """Render a 32-byte digest as an Inkan **Seal v3** PNG (8-bit indexed, 5 colours).

    Seal v3 is original work: structure is driven by bit-interleaved extended Golay [24,12,8]
    blocks (cell profiles 24/48/72), so any two distinct seals differ in at least 8 interior
    cells by construction; the kind selects the rotational symmetry order.
    See `inkan_standard.seal`.

    The `scale` argument is an integer nearest-neighbour upscale (1 = native 224x224).
    """
    from . import seal
    return seal.seal_png(digest, kind="", scale=scale)


def digest_to_lifehash_png_v1(digest: bytes, scale: int = 8) -> bytes:
    """LEGACY v1 seals only. Permanently removed -- a tombstone, kept so the removal is explicit
    rather than a silent `AttributeError`.

    v1 seals were rendered by **LifeHash** ((c) 2019-2022 Blockchain Commons, LLC,
    BSD-2-Clause-Patent) -- third-party work, not Inkan's. It was deleted outright on 2026-07-09
    and no copy is retained anywhere: nothing here ships, imports, or depends on it. No v1 seal was
    ever published, so there is nothing to re-render.

    New seals use `digest_to_inkan_png` (Seal v3, original work). The **digest is the on-chain
    anchor** (SPEC.md 1.2, 3), not the image, so no anchored fingerprint or canary was invalidated
    by the renderer change -- only the picture differs.
    """
    raise NotImplementedError(
        "LifeHash (v1) rendering was removed from inkan_standard and no copy is retained. It is third-party "
        "work ((c) Blockchain Commons, BSD-2-Clause-Patent). Use inkan_standard.seal (v3) for new seals; no "
        "v1 seal was ever published, so none needs re-rendering."
    )


def fingerprint_image_png(payload: bytes, adopter: str, version: int = 1, scale: int = 8) -> bytes:
    return digest_to_inkan_png(fingerprint_digest(payload, adopter, version), scale)


def png_chunk_tags(png: bytes) -> list:
    """List the chunk tags in a PNG, in order — for the clean-metadata guarantee (see below)."""
    assert png[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
    i, tags = 8, []
    while i < len(png):
        n = struct.unpack(">I", png[i:i + 4])[0]
        tags.append(png[i + 4:i + 8].decode("ascii", "replace"))
        i += 12 + n
    return tags


def _png_rgb888(w: int, h: int, rgb: bytes, scale: int = 1) -> bytes:
    """Minimal stdlib RGB888 PNG with integer nearest-neighbour upscaling.

    **Clean-metadata rule (project-wide): every Inkan image is written with NO metadata.** This
    writer emits ONLY the three mandatory chunks — IHDR, IDAT, IEND. It never writes an ancillary
    chunk: no ``tEXt``/``iTXt``/``zTXt`` (author, software, comment), no ``tIME`` (timestamp), no
    ``pHYs`` (physical dimensions), no ``eXIf``. So an Inkan PNG carries nothing that could identify
    the machine, the software build, the time, or the subject. Any port MUST match this (assert with
    :func:`png_chunk_tags`), and callers MUST also write it to a non-identifying *filename* — never
    embed a pubkey / fingerprint / name / paymail / timestamp in the file name."""
    sw, sh = w * scale, h * scale
    rows = bytearray()
    for y in range(sh):
        base = (y // scale) * w * 3
        rows.append(0)  # filter byte
        for x in range(sw):
            i = base + (x // scale) * 3
            rows += rgb[i:i + 3]

    def chunk(tag, data):
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xffffffff)

    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", sw, sh, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(rows), 9))
            + chunk(b"IEND", b""))
