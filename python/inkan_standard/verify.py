# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 RexStarBSV
# Inkan verification path (see LICENSE-VERIFY and NOTICE). Repository default licence: BSL 1.1.
"""
inkan_standard.verify -- independent verification of Inkan seals, fingerprints and canaries.

The point of this module: **you do not have to trust the party that showed you an Inkan.**
Everything an Inkan asserts is recomputable from public inputs, and this verifier recomputes
it from scratch and compares. A phishing lookalike -- a seal that merely *resembles* a target
-- fails, because it is not the byte-exact render of the claimed (data, kind).

Three things can be verified:

  * SEAL      given (data, kind), recompute the canonical seal. If a presented PNG is
              supplied, decode it and compare pixel-for-pixel: MATCH iff it is the genuine
              render (re-encoding and integer upscales are tolerated; a different image is not).
  * FINGERPRINT  recompute the namespaced digest and compare to a claimed hex.
  * CANARY    verify a warrant-canary record's signature and freshness.

And the verifier verifies ITSELF: `selftest` runs this engine against the pinned
cross-language vectors, so a tampered or drifted copy is caught before it judges anything.

Stdlib-only throughout: seal + fingerprint verification always were, and canary signature
checking falls back to the built-in pure-Python secp256k1 verifier (`inkan_standard._secp256k1`) when
`bitcoinx` is absent. No PIL, no numpy, no network.
"""
from __future__ import annotations

import hashlib
import os
import struct
import zlib
from typing import NamedTuple, Optional

from . import seal as _seal
from .seed import CODE_PREFIX, inkan_code, inkan_short_code, inkan_seed


class Result(NamedTuple):
    ok: bool
    summary: str
    detail: dict


# ----------------------------------------------------------------- minimal PNG decode
class _PNG(NamedTuple):
    width: int
    height: int
    rgb: bytes            # width*height*3, row-major


#: SPEC §6.1 rule 2 (E24): the only chunks a verifiable PNG may carry. An allow-list, because PNG keeps
#: adding chunk types that change what a viewer draws: E12's list of forbidden chunks (tRNS, gAMA,
#: iCCP, sRGB, cHRM, sBIT, bKGD and the animation chunks) missed cICP, a colour space, and eXIf, an
#: orientation, and a genuine seal carrying either verified GENUINE here while a browser drew it in
#: other colours or rotated.
_ALLOWED_CHUNKS = frozenset((b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tEXt", b"zTXt", b"iTXt",
                             b"pHYs", b"tIME"))

#: Chunks a conformant viewer MUST honour, which change the picture a human sees while leaving the
#: decoded RGB identical (E12). The allow-list refuses them with every other chunk; they are named
#: here only so the refusal can say why they matter.
_RENDERING_CHUNKS = frozenset(
    (b"tRNS", b"gAMA", b"iCCP", b"sRGB", b"cHRM", b"sBIT", b"bKGD", b"cICP", b"eXIf", b"mDCV",
     b"cLLI", b"acTL", b"fcTL", b"fdAT"))

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _chunk_name(t: bytes) -> str:
    return t.decode("latin-1") if all(0x20 < b < 0x7F for b in t) else t.hex()


def decode_png_rgb(data: bytes) -> _PNG:
    """Decode a presented file under the verifiable-PNG profile of SPEC §6.1 (E24) to flat RGB, or
    raise ValueError saying which rule it breaks.

    The profile accepts every honest re-encoding of a seal (any deflate settings, any scanline
    filter, indexed or truecolour, benign metadata) and nothing whose appearance can differ from the
    pixels compared here: the signature, then chunks with correct CRCs ending exactly at IEND; only
    the allowed chunk types, in the allowed order; 8-bit truecolour or indexed colour, not interlaced;
    a palette that covers every index; and one zlib stream (method 8, no preset dictionary, a correct
    Adler-32) that ends with the last IDAT and inflates to exactly the size IHDR declares."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValueError("a presented image is bytes, got %s" % type(data).__name__)
    data = bytes(data)
    if data[:8] != _PNG_SIGNATURE:
        raise ValueError("not a PNG: the file does not begin with the PNG signature")

    # Rule 1: a sequence of chunks with correct CRCs, ending exactly where IEND ends.
    chunks = []
    pos = 8
    while True:
        if pos + 12 > len(data):
            raise ValueError("not a verifiable PNG: the file ends inside a chunk, or has no IEND "
                             "(SPEC §6.1 rule 1)")
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        ctype = data[pos + 4:pos + 8]
        if length > 0x7FFFFFFF:
            raise ValueError("not a verifiable PNG: a chunk length is over 2^31 - 1 (SPEC §6.1 rule 1)")
        if pos + 12 + length > len(data):
            raise ValueError("not a verifiable PNG: chunk %s runs past the end of the file "
                             "(SPEC §6.1 rule 1)" % _chunk_name(ctype))
        body = data[pos + 8:pos + 8 + length]
        (crc,) = struct.unpack(">I", data[pos + 8 + length:pos + 12 + length])
        if zlib.crc32(ctype + body) & 0xFFFFFFFF != crc:
            raise ValueError("not a verifiable PNG: chunk %s has a wrong CRC (SPEC §6.1 rule 1)"
                             % _chunk_name(ctype))
        if ctype not in _ALLOWED_CHUNKS:
            why = (", which changes what a viewer draws without changing the pixels compared"
                   if ctype in _RENDERING_CHUNKS else "")
            raise ValueError("PNG carries chunk %s%s; a verifiable PNG may carry only IHDR, PLTE, "
                             "IDAT, IEND, tEXt, zTXt, iTXt, pHYs and tIME (SPEC §6.1 rule 2)"
                             % (_chunk_name(ctype), why))
        chunks.append((ctype, body))
        pos += 12 + length
        if ctype == b"IEND":
            break
    if pos != len(data):
        raise ValueError("not a verifiable PNG: %d byte(s) follow IEND (SPEC §6.1 rule 1)"
                         % (len(data) - pos))

    # Rule 3: order.
    types = [t for t, _ in chunks]
    idat_at = [i for i, t in enumerate(types) if t == b"IDAT"]
    if types[0] != b"IHDR" or types.count(b"IHDR") != 1:
        raise ValueError("not a verifiable PNG: IHDR must come first and appear once (SPEC §6.1 rule 3)")
    if chunks[-1][1]:
        raise ValueError("not a verifiable PNG: IEND must have no data (SPEC §6.1 rule 3)")
    if not idat_at:
        raise ValueError("not a verifiable PNG: no IDAT chunk (SPEC §6.1 rule 6)")
    if idat_at != list(range(idat_at[0], idat_at[-1] + 1)):
        raise ValueError("not a verifiable PNG: the IDAT chunks are not consecutive (SPEC §6.1 rule 3)")
    for name, before_idat in ((b"PLTE", True), (b"pHYs", True), (b"tIME", False)):
        at = [i for i, t in enumerate(types) if t == name]
        if len(at) > 1 or (before_idat and at and at[0] > idat_at[0]):
            raise ValueError("not a verifiable PNG: %s must appear at most once%s (SPEC §6.1 rule 3)"
                             % (name.decode(), ", before the first IDAT" if before_idat else ""))

    # Rule 4: the header.
    ihdr = chunks[0][1]
    if len(ihdr) != 13:
        raise ValueError("not a verifiable PNG: IHDR must hold 13 bytes (SPEC §6.1 rule 4)")
    width, height, depth, ctype, comp, filt, interlace = struct.unpack(">IIBBBBB", ihdr)
    if not (1 <= width <= 0x7FFFFFFF and 1 <= height <= 0x7FFFFFFF):
        raise ValueError("not a verifiable PNG: width and height must be from 1 to 2^31 - 1")
    if depth != 8:
        raise ValueError(f"unsupported bit depth {depth}; a verifiable PNG is 8-bit (SPEC §6.1 rule 4)")
    if ctype not in (2, 3):
        raise ValueError(f"unsupported colour type {ctype}; a verifiable PNG is truecolour (2) or "
                         f"indexed-colour (3) (SPEC §6.1 rule 4)")
    if comp != 0 or filt != 0:
        raise ValueError("not a verifiable PNG: IHDR compression and filter methods must be 0 "
                         "(SPEC §6.1 rule 4)")
    if interlace != 0:
        raise ValueError("interlaced PNG; a verifiable PNG is not interlaced (SPEC §6.1 rule 4)")

    # Rule 5: the palette (a suggested palette in a truecolour image is allowed and ignored).
    plte = next((b for t, b in chunks if t == b"PLTE"), None)
    if ctype == 3:
        if plte is None:
            raise ValueError("not a verifiable PNG: an indexed-colour image needs a PLTE "
                             "(SPEC §6.1 rule 5)")
        if len(plte) % 3 or not 1 <= len(plte) // 3 <= 256:
            raise ValueError("not a verifiable PNG: PLTE must hold 1 to 256 three-byte entries "
                             "(SPEC §6.1 rule 5)")

    # Rule 7: metadata lengths.
    for t, b in chunks:
        if (t == b"pHYs" and len(b) != 9) or (t == b"tIME" and len(b) != 7):
            raise ValueError("not a verifiable PNG: %s must hold %d bytes (SPEC §6.1 rule 7)"
                             % (t.decode(), 9 if t == b"pHYs" else 7))

    # Rule 6: one zlib stream, inflating to exactly the declared size.
    channels = 3 if ctype == 2 else 1
    stride = width * channels
    # Bounded decompression. IHDR says exactly how many bytes a valid image expands to, so anything
    # past that is a compression bomb and is never materialised: a ~200 KB IDAT can expand to hundreds
    # of MB, and the same rules run in a browser page meant for permanent on-chain inscription.
    want = (stride + 1) * height
    z = b"".join(b for t, b in chunks if t == b"IDAT")
    if (len(z) < 2 or z[0] & 0x0F != 8 or z[0] >> 4 > 7 or ((z[0] << 8) | z[1]) % 31
            or z[1] & 0x20):
        raise ValueError("not a verifiable PNG: the image data is not a zlib stream with compression "
                         "method 8 and no preset dictionary (SPEC §6.1 rule 6)")
    try:
        dz = zlib.decompressobj()
        raw = dz.decompress(z, want + 1)
    except zlib.error as e:
        raise ValueError("corrupt PNG: %s (SPEC §6.1 rule 6)" % e) from None
    if len(raw) > want:
        raise ValueError("corrupt PNG: IDAT expands beyond the size IHDR declares "
                         "(compression bomb, or a mismatched header)")
    if not dz.eof:
        raise ValueError("corrupt PNG: the zlib stream does not end (SPEC §6.1 rule 6)")
    if dz.unused_data:
        raise ValueError("not a verifiable PNG: %d byte(s) follow the end of the zlib stream "
                         "(SPEC §6.1 rule 6)" % len(dz.unused_data))
    if len(raw) != want:
        raise ValueError("corrupt PNG: wrong scanline length")

    prev = bytearray(stride)
    out = bytearray()
    off = 0
    entries = len(plte) // 3 if plte is not None else 0
    for _y in range(height):
        ftype = raw[off]; off += 1
        line = bytearray(raw[off:off + stride]); off += stride
        _unfilter(line, prev, ftype, channels)
        if ctype == 3:
            if max(line) >= entries:
                raise ValueError("not a verifiable PNG: a pixel's palette index is not less than the "
                                 "number of PLTE entries (SPEC §6.1 rule 5)")
            for idx in line:
                out += plte[idx * 3:idx * 3 + 3]
        else:
            out += line
        prev = line
    return _PNG(width, height, bytes(out))


def read_embedded_tag(data: bytes) -> dict:
    """Extract Inkan's ``iTXt`` self-description (code, kind) from a PNG, if present. Returns {} if
    absent. The values are an UNTRUSTED HINT -- attacker-controllable -- so a caller must verify by
    recomputing, never by believing the tag."""
    out = {}
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return out
    pos = 8
    while pos + 8 <= len(data):
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        name = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + length]
        pos += 12 + length
        if name == b"iTXt":
            nul = body.find(b"\x00")
            keyword = body[:nul].decode("latin-1", "replace")
            text = body[nul + 5:].decode("utf-8", "replace")   # skip 4 flag/lang bytes + 1 nul
            if keyword == "inkan-code":
                out["code"] = text
            elif keyword == "inkan-kind":
                out["kind"] = text
        elif name == b"IEND":
            break
    return out


def _unfilter(line: bytearray, prev: bytearray, ftype: int, bpp: int) -> None:
    if ftype == 0:
        return
    for i in range(len(line)):
        a = line[i - bpp] if i >= bpp else 0
        b = prev[i]
        c = prev[i - bpp] if i >= bpp else 0
        if ftype == 1:      # Sub
            line[i] = (line[i] + a) & 0xFF
        elif ftype == 2:    # Up
            line[i] = (line[i] + b) & 0xFF
        elif ftype == 3:    # Average
            line[i] = (line[i] + ((a + b) >> 1)) & 0xFF
        elif ftype == 4:    # Paeth
            p = a + b - c
            pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
            pr = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
            line[i] = (line[i] + pr) & 0xFF
        else:
            raise ValueError(f"unknown PNG filter {ftype}")


#: Returned when an image has valid upscale dimensions but non-uniform blocks -- distinct from None
#: (wrong dimensions), because the two mean very different things to whoever is reading the verdict.
_NON_UNIFORM = object()


def _downscale_to_native(png: _PNG):
    """If the image is an exact integer upscale of the native canvas, reduce it to native
    RGB (nearest-neighbour, matching the writer). Returns None if it is not a clean multiple
    -- a resampled or cropped image is not the genuine seal and must not be coerced into one."""
    n = _seal.CANVAS
    if png.width != png.height or png.width % n != 0:
        return None
    scale = png.width // n
    if scale == 1:
        return png.rgb
    out = bytearray(n * n * 3)
    W = png.width
    for y in range(n):
        for x in range(n):
            src = ((y * scale) * W + (x * scale)) * 3
            dst = (y * n + x) * 3
            out[dst:dst + 3] = png.rgb[src:src + 3]

    # EVERY pixel must agree, not just the one per block we sampled above.
    #
    # Sampling alone accepted any image whose block top-left pixels matched, leaving the other
    # scale**2 - 1 pixels of each block entirely attacker-controlled: at scale 8 that is 98.44% of
    # the image. A forgery 98.44% pixel-identical to one entity's genuine seal verified GENUINE as a
    # DIFFERENT entity's, which is precisely the substitution a trust mark exists to prevent. The
    # browser path compounded it by displaying the subsample rather than the file the user chose, so
    # the discarded 98.44% was never shown to anyone.
    #
    # Reconstructing the upscale and comparing whole rows keeps this at one linear pass of C-speed
    # bytes comparisons rather than 3.2M per-pixel checks in Python.
    row = bytearray(W * 3)
    for y in range(n):
        base = y * n * 3
        for x in range(n):
            px = out[base + x * 3: base + x * 3 + 3]
            row[x * scale * 3:(x + 1) * scale * 3] = px * scale
        want = bytes(row)
        for dy in range(scale):
            off = ((y * scale + dy) * W) * 3
            if png.rgb[off:off + W * 3] != want:
                return _NON_UNIFORM     # right dimensions, but the blocks disagree internally
    return bytes(out)


# ----------------------------------------------------------------- seal
def canonical_seal(data, kind: str = "") -> dict:
    """The ground truth for a given (data, kind): the digest and the seal's hashes."""
    digest = hashlib.sha256(inkan_seed(data, kind)).digest()
    rgb = bytes(c for px in _seal.seal_rgb(digest, kind) for c in px)
    png = _seal.seal_png(digest, kind)
    return {
        "kind": kind,
        "code": CODE_PREFIX + digest.hex(),                 # self-identifying full code (ik1 + digest)
        "short_code": CODE_PREFIX + digest.hex()[:16],      # ik1 + 16-hex filename/display label
        "digest_hex": digest.hex(),
        "rgb_sha256": hashlib.sha256(rgb).hexdigest(),
        # Deliberately no png_sha256. BRC-145: "the cross-language invariant is the decoded RGB
        # pixel content, not the compressed bytes (deflate output is per-implementation)". Computing
        # one here invites a caller to pin it, and an honest port emitting a differently-compressed
        # but pixel-identical PNG would then read as a failure.
        "rgb": rgb,
        "png": png,
    }


def verify_seal(data, kind: str = "", presented_png: Optional[bytes] = None) -> Result:
    """Recompute the canonical seal for (data, kind). If a PNG is presented, decode it and
    compare pixel-for-pixel against the genuine render. Any kind string is valid (SPEC §4):
    reserved kinds use the curated table, everything else derives deterministically."""
    truth = canonical_seal(data, kind)
    detail = {k: truth[k] for k in ("kind", "code", "short_code", "digest_hex", "rgb_sha256")}
    detail["reserved_kind"] = kind in _seal.KINDS
    if presented_png is None:
        return Result(True, "recomputed canonical seal (no image to compare)", detail)
    try:
        png = decode_png_rgb(presented_png)
    except ValueError as e:
        return Result(False, f"presented image rejected: {e}", detail)
    native = _downscale_to_native(png)
    detail["presented_size"] = f"{png.width}x{png.height}"
    if native is _NON_UNIFORM:
        detail["tampered_blocks"] = True
        return Result(False,
                      f"presented image is {png.width}x{png.height}, a valid "
                      f"{png.width // _seal.CANVAS}x upscale of {_seal.CANVAS}, but its pixel blocks "
                      f"are not uniform: pixels WITHIN blocks differ, so this is not an upscale of "
                      f"any seal. A clean upscale repeats each pixel exactly.", detail)
    if native is None:
        return Result(False,
                      f"presented image is {png.width}x{png.height}, not an integer multiple of "
                      f"{_seal.CANVAS}: cannot be the genuine seal", detail)
    match = native == truth["rgb"]
    detail["presented_rgb_sha256"] = hashlib.sha256(native).hexdigest()
    tagv = read_embedded_tag(presented_png)
    if tagv.get("code"):
        # the image CLAIMS a code in its metadata -- cross-check it against the truth (never trust it)
        detail["embedded_code"] = tagv["code"]
        detail["embedded_code_matches"] = (tagv["code"] == truth["code"])
    return Result(match,
                  "GENUINE: presented seal is the exact render for this (data, kind)" if match
                  else "MISMATCH: presented seal is NOT the genuine render (possible lookalike)",
                  detail)


# ----------------------------------------------------------------- fingerprint
def verify_fingerprint(payload, adopter: str, expect_hex: Optional[str] = None,
                       version: int = 1) -> Result:
    # `adopter` is REQUIRED and deliberately has no default: it selects the fingerprint namespace,
    # so a default would let a caller silently verify against the wrong one and read as a pass.
    # `version` is an explicit input too (SPEC §0 P5, §7 E22): a genuine version-2 fingerprint checked
    # without it read MISMATCH, as if the bytes had been altered. It must be a positive integer.
    from .fingerprint import fingerprint_hex
    got = fingerprint_hex(payload if isinstance(payload, (bytes, bytearray)) else str(payload).encode(),
                          adopter, version)
    detail = {"adopter": adopter, "version": version, "fingerprint_hex": got}
    if expect_hex is None:
        return Result(True, "recomputed fingerprint", detail)
    match = got.lower() == expect_hex.strip().lower()
    detail["expected_hex"] = expect_hex.strip().lower()
    return Result(match, "MATCH" if match else "MISMATCH: fingerprint does not equal the claimed value",
                  detail)


# ----------------------------------------------------------------- canary
def verify_canary(record, signature_hex: str, pubkey_hex: str,
                  max_age_days: int = 35) -> Result:
    """`record` is an object, or its wire form (bytes or text), which must then be exactly the
    record's canonical bytes (SPEC §8 E23)."""
    try:
        from . import canary
    except Exception as e:  # pragma: no cover
        return Result(False, f"canary module unavailable: {e}", {})
    try:
        st = canary.status(record, signature_hex, pubkey_hex, max_age_days=max_age_days)
    except ModuleNotFoundError:
        return Result(False, "canary signature verification needs `bitcoinx` (not installed)",
                      {"hint": "pip install bitcoinx"})
    except canary.UnsupportedCanaryVersion as e:
        # Unknown record version (SPEC §8 E2): UNSUPPORTED, explicitly not INVALID.
        return Result(False, "UNSUPPORTED: %s" % e, {"status": "UNSUPPORTED"})
    detail = {"status": st}
    try:
        rec, _wire = canary._record_of(record)
    except canary.MalformedCanaryInput:
        rec = None
    if isinstance(rec, dict):
        detail.update({"seq": rec.get("seq"), "domain": rec.get("domain")})
    if st == "MALFORMED":
        try:
            canary.verify(record, signature_hex, pubkey_hex)
        except canary.MalformedCanaryInput as e:
            detail["reason"] = str(e)
    return Result(st == "OK", f"canary status: {st}", detail)


# ----------------------------------------------------------------- self-verification
def selftest(vectors_path: Optional[str] = None) -> Result:
    """Prove THIS engine renders the canonical standard, by reproducing the pinned vectors.
    A verifier that cannot verify itself must not be trusted to verify anything."""
    import json
    import pathlib
    if vectors_path is None:
        # Installed wheel first, repository checkout second. The module docstring promises the
        # verifier verifies ITSELF; shipping that sentence in a wheel that cannot execute it made
        # the promise true only for people who had the source -- i.e. not the people relying on it.
        packaged = pathlib.Path(__file__).resolve().parent / "vectors" / "seal-v3-vectors.json"
        if packaged.is_file():
            vectors_path = packaged
        else:
            vectors_path = (pathlib.Path(__file__).resolve().parents[2] /
                            "test-vectors" / "seal-v3-vectors.json")
    p = pathlib.Path(vectors_path)
    if not p.is_file():
        return Result(False, f"vectors not found at {p}", {})
    doc = json.loads(p.read_text())
    if doc.get("seal_version") != _seal.SEAL_VERSION:
        return Result(False, f"vector seal_version {doc.get('seal_version')} != engine {_seal.SEAL_VERSION}", {})
    bad = 0
    for v in doc["sampled"]:
        digest = bytes.fromhex(v["digest_hex"])
        words, pix, core = _seal.seal_fields(digest, v["kind"])
        rgb = bytes(c for px in _seal.seal_rgb_from_fields(words, pix, core, v["kind"]) for c in px)
        if list(words) != v["words"] or pix != v["palette_ix"] or core != v["core_pattern"] \
                or hashlib.sha256(rgb).hexdigest() != v["rgb_sha256"]:
            bad += 1
    n = len(doc["sampled"])
    # SPEC §1 E14: text is checked against the Unicode database the normaliser uses, and the
    # self-test says which one, so a reader can see why an input this build rejects may be accepted
    # by a build on a newer runtime (and never answered differently).
    from .seed import UNICODE_VERSION
    return Result(bad == 0, f"self-test: {n - bad}/{n} pinned vectors reproduced; "
                            f"text is checked against Unicode {UNICODE_VERSION}",
                  {"vectors": n, "mismatches": bad, "seal_version": _seal.SEAL_VERSION,
                   "unicode_version": UNICODE_VERSION})


# ----------------------------------------------------------------- savable report
VERIFY_VERSION = "1.0"


def build_report(command: str, inputs: dict, res: "Result") -> dict:
    """A self-contained, archivable record of one verification: what was checked, when, by
    which standard, and the verdict. Deterministic except for the timestamp, so two runs of
    the same check produce the same evidence hashes."""
    import datetime
    detail = {k: v for k, v in res.detail.items() if k not in ("rgb", "png")}
    return {
        "report": "inkan-verification",
        "verify_version": VERIFY_VERSION,
        "seal_version": _seal.SEAL_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "command": command,
        "inputs": inputs,
        "verdict": "PASS" if res.ok else "FAIL",
        "summary": res.summary,
        "detail": detail,
    }


def _report_markdown(rep: dict) -> str:
    lines = [
        f"# Inkan verification report",
        "",
        f"**Verdict:** {'✅ PASS' if rep['verdict'] == 'PASS' else '❌ FAIL'} — {rep['summary']}",
        "",
        f"- Generated: `{rep['generated_utc']}`",
        f"- Command: `{rep['command']}`",
        f"- Inkan Seal standard: v{rep['seal_version']} · verifier v{rep['verify_version']}",
        "",
        "## Inputs",
        "",
    ]
    for k, v in rep["inputs"].items():
        lines.append(f"- **{k}:** `{v}`")
    lines += ["", "## Evidence", ""]
    for k, v in rep["detail"].items():
        lines.append(f"- **{k}:** `{v}`")
    lines += ["", "---",
              "_Recomputed from public inputs by `inkan_standard.verify`; nothing presented was trusted. "
              "Reproduce by re-running the command above._", ""]
    return "\n".join(lines)


def write_report(path: str, rep: dict) -> None:
    import json
    if path.endswith(".md"):
        text = _report_markdown(rep)
    else:
        text = json.dumps(rep, indent=2) + "\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


# ----------------------------------------------------------------- CLI
def _read_data(arg: str):
    """A command-line value: the bytes of a file for ``@file``, otherwise the TEXT as typed.

    What a person types or pastes is text, and an anchor of text is taken over its NFC form (SPEC §1
    E19). This returned ``arg.encode("utf-8")`` for typed input, so `seal --data` hashed typed text as
    raw bytes: a decomposed "café" (as macOS filenames and some keyboards produce it) gave
    ik191d9326afef7a… here and ik17288300319e48… in every library and the web verifier, and a genuine
    seal read MISMATCH. Only a file is bytes. Callers that need bytes (a fingerprint payload, which
    §7 defines as bytes) encode the text as UTF-8 themselves."""
    if arg.startswith("@"):
        with open(arg[1:], "rb") as fh:
            return fh.read()
    return arg


def _fingerprint_version(text: str) -> int:
    """`--version`: ASCII decimal digits naming a positive integer (SPEC §7 E22)."""
    import argparse
    if not text.isascii() or not text.isdigit() or int(text) < 1:
        raise argparse.ArgumentTypeError("must be a positive integer (1, 2, 3, ...), got %r" % text)
    return int(text)


def main(argv=None) -> int:
    import argparse
    import json

    ap = argparse.ArgumentParser(
        prog="inkan-verify",
        description="Independently verify an Inkan seal, fingerprint, or warrant canary. "
                    "Recomputes everything from public inputs — trusts nothing presented.")
    # shared flags, accepted either before or after the subcommand
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    common.add_argument("--report", help="write a savable verification report (.md or .json)")
    ap.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--report", help=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("seal", parents=[common], help="verify a seal matches (data, kind)")
    s.add_argument("--data", required=True,
                   help="the sealed text, as typed (NFC-normalised, SPEC §1), or @file for the raw "
                        "bytes of a file")
    s.add_argument("--kind", default="", help="any kind string (SPEC §4); reserved: "
                   f"{', '.join(sorted(_seal.KINDS))}; others derive as [ns:]name[@t1|t2|t3]")
    s.add_argument("--seal", help="presented seal PNG to check against the genuine render")
    s.add_argument("--render", help="write the canonical seal PNG here")
    s.add_argument("--scale", type=int, default=1, help="integer upscale for --render")
    s.add_argument("--no-tag", action="store_true", help="render a metadata-free canonical PNG "
                                                       "(default embeds the full code as an iTXt hint)")

    f = sub.add_parser("fingerprint", parents=[common], help="verify a namespaced fingerprint digest")
    f.add_argument("--payload", required=True,
                   help="text (hashed as its UTF-8 bytes: a fingerprint payload is bytes, SPEC §7), "
                        "or @file for the raw bytes of a file")
    f.add_argument("--adopter", required=True, help="the adopter namespace the digest was made under")
    f.add_argument("--version", type=_fingerprint_version, default=1,
                   help="the fingerprint version the digest was made under: a positive integer "
                        "(default 1; SPEC §7)")
    f.add_argument("--expect", help="claimed fingerprint hex to compare against")

    c = sub.add_parser("canary", parents=[common], help="verify a warrant-canary record")
    c.add_argument("--record", required=True,
                   help="the canary record exactly as published, its canonical JSON (SPEC §8), as "
                        "@file or as text; whitespace around it is ignored")
    c.add_argument("--sig", required=True, help="signature hex")
    c.add_argument("--pubkey", required=True, help="signer public key hex")
    c.add_argument("--max-age-days", type=int, default=35)

    sub.add_parser("selftest", parents=[common], help="prove this verifier renders the canonical standard")

    args = ap.parse_args(argv)

    if args.cmd == "seal":
        presented = None
        if args.seal:
            with open(args.seal, "rb") as fh:
                presented = fh.read()
        data = _read_data(args.data)              # text as typed, or a file's bytes (E19)
        try:
            res = verify_seal(data, args.kind, presented)
        except ValueError as e:                   # E4 / E14: input the standard refuses
            print(f"✗ cannot seal this input: {e}")
            return 2
        code = inkan_code(data, args.kind)
        short = inkan_short_code(data, args.kind)
        res.detail.setdefault("code", code)
        res.detail.setdefault("short_code", short)
        if args.render:
            digest = hashlib.sha256(inkan_seed(data, args.kind)).digest()
            path = args.render
            if os.path.isdir(path):           # a directory -> name the file by the SHORT code
                path = os.path.join(path, f"inkan-{short}.png")
            with open(path, "wb") as fh:
                fh.write(_seal.seal_png(digest, args.kind, scale=args.scale, tag=not args.no_tag))
            res.detail["rendered"] = path
        inputs = {"data": args.data, "kind": args.kind, "seal": args.seal or "(none)"}
    elif args.cmd == "fingerprint":
        try:
            res = verify_fingerprint(_read_data(args.payload), args.adopter, args.expect, args.version)
        except ValueError as e:                   # E4 / E14 / E21: an adopter name the profile refuses
            print(f"✗ cannot compute this fingerprint: {e}")
            return 2
        inputs = {"payload": args.payload, "adopter": args.adopter, "version": args.version,
                  "expect": args.expect or "(none)"}
    elif args.cmd == "canary":
        # The record is read as its wire bytes, so the canonical-bytes rule applies (SPEC §8 E23
        # rule 4); only whitespace around it, such as the line feed that ends a file, is dropped.
        wire = _read_data(args.record)
        wire = (wire.encode("utf-8") if isinstance(wire, str) else wire).strip(b" \t\r\n")
        res = verify_canary(wire, args.sig, args.pubkey, args.max_age_days)
        inputs = {"record": args.record, "pubkey": args.pubkey, "max_age_days": args.max_age_days}
    else:
        res = selftest()
        inputs = {}

    if args.report:
        rpath = args.report
        if os.path.isdir(rpath):
            short = res.detail.get("short_code", "report")
            rpath = os.path.join(rpath, f"inkan-{short}.md")
        write_report(rpath, build_report(args.cmd, inputs, res))
        print(f"  report: {rpath}")

    if args.json:
        print(json.dumps({"ok": res.ok, "summary": res.summary,
                          "detail": {k: v for k, v in res.detail.items()
                                     if k not in ("rgb", "png")}}, indent=2))
    else:
        mark = "✓" if res.ok else "✗"
        print(f"{mark} {res.summary}")
        for k, v in res.detail.items():
            if k not in ("rgb", "png"):
                print(f"    {k}: {v}")
    return 0 if res.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
