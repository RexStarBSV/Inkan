# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 RexStarBSV
# Inkan verification path (see LICENSE-VERIFY and NOTICE). Repository default licence: BSL 1.1.
"""
inkan_standard.seed — Inkan *glyph* seed domain separation.

Python mirror of `js/src/seed.js` (and of `Inkan.kt`), so a seal rendered here is byte-identical to
the one every conforming implementation renders for the same `(data, kind)`.

Two different domains exist in this package and must not be confused:

  * **glyph domain** (here)                          ``inkan/v1\\x00``
  * **tamper-fingerprint domain** (`fingerprint.py`) ``<adopter>/inkan/v1\\x00``

The glyph domain belongs to the STANDARD (``inkan/v1``); the fingerprint domain is namespaced per
ADOPTER, so one adopter's fingerprints never collide with another's while both build on the same
standard.

Both are versioned by their *seed scheme*, not by the renderer. `SEAL_VERSION` in `inkan_standard.seal` is
orthogonal: a new seal design is a new SEAL_VERSION added beside v3, never a replacement (SPEC §0),
and no seal version changes the digest, so nothing anchored on-chain is affected by one. This is
why the glyph domain is ``v1`` while the seal renderer is ``v3``.
**Bumping the domain below would invalidate every glyph digest — don't.**
"""
import unicodedata
from typing import Union

__all__ = ["INKAN_DOMAIN", "CODE_PREFIX", "SHORT_CODE_LEN", "FULL_CODE_LEN", "UNICODE_VERSION",
           "inkan_seed", "inkan_digest", "inkan_code", "inkan_short_code", "code_to_digest_hex",
           "reject_unassigned"]

#: Fixed, published domain prefix for the Inkan standard. Bump the trailing version only if the
#: *seed scheme* changes (it has not since v1). This string lives inside every glyph digest.
INKAN_DOMAIN = b"inkan/v1\x00"

#: Self-identifying code prefix: ``ik`` marks an Inkan code; the digit is the code-format / hash
#: version. ``ik1`` = SHA-256 over glyph domain ``inkan/v1``. When SHA-256 is eventually retired,
#: ``ik2…`` codes are unambiguously distinguishable — this is what keeps the anchor hash-agile for
#: 100 years (see docs/future-provisions.md §1.1). The prefix lives on the code STRING only; the raw
#: 32-byte digest that drives v1 rendering is unchanged.
CODE_PREFIX = "ik1"

#: Length (hex chars) of the SHORT code body. 16 hex = 64 bits: collision-safe to billions and
#: forgery-resistant (~2^64), while readable. The short code is a genuine PREFIX of the full digest,
#: so it is auditable (recompute, check). It is a label only; verification uses the full digest/seal.
SHORT_CODE_LEN = 16


#: The version of the Unicode Character Database this interpreter's NFC normaliser uses. The E14 check
#: below reads the same database, so the two can never disagree, and the self-test reports it.
UNICODE_VERSION = unicodedata.unidata_version


def _is_noncharacter(cp: int) -> bool:
    """The 66 noncharacters: U+FDD0..U+FDEF, and the last two code points of each of the 17 planes.
    They are permanently unassigned and normalise to themselves in every Unicode version."""
    return 0xFDD0 <= cp <= 0xFDEF or (cp & 0xFFFE) == 0xFFFE


def reject_unassigned(text: str, what: str) -> None:
    """Refuse text that holds a code point this Unicode database leaves unassigned (SPEC §1 E14).

    NFC treats a code point it does not know as an unassigned starter. A newer database may know the
    same code point as a combining mark or a composable letter and normalise the string differently,
    so a runtime that guessed would give a different anchor from one that knew. Unicode's stability
    policy guarantees that two databases which both assign every code point of a string normalise it
    the same way, now and in every later version; refusing is therefore the one answer that never
    disagrees with another conforming implementation. General_Category Cn is the test, with the 66
    noncharacters excepted, read from the same `unicodedata` the normaliser uses.
    """
    if not isinstance(text, str):
        raise TypeError("%s must be text (str), got %s" % (what, type(text).__name__))
    if text.isascii():
        return
    bad = [c for c in set(text)
           if unicodedata.category(c) == "Cn" and not _is_noncharacter(ord(c))]
    if bad:
        pos = min(text.index(c) for c in bad)
        raise ValueError(
            "%s contains U+%04X at position %d, which is unassigned in the Unicode %s database this "
            "implementation normalises with. Such text MUST be rejected, never normalised or hashed "
            "(SPEC §1 E14)" % (what, ord(text[pos]), pos, UNICODE_VERSION))


def _norm(s: str) -> str:
    """NFC-normalise text so visually-identical strings (é as one codepoint vs e + combining
    accent) produce the SAME Inkan. Applied to every string input before UTF-8 encoding."""
    return unicodedata.normalize("NFC", s)


def _encode_utf8(text: str, what: str) -> bytes:
    """UTF-8 encode, REJECTING anything unencodable rather than substituting for it (SPEC §4 E4).

    Python raised `UnicodeEncodeError` here by accident of the default error handler, JavaScript's
    TextEncoder silently produced `EF BF BD` (U+FFFD), and Kotlin's `toByteArray` substituted too. So
    the same input yielded three different anchors and two of the three ports believed they had
    succeeded -- the worst shape a divergence can take, because nothing fails.

    Substitution is the specific danger: every unpaired surrogate would collapse onto the SAME
    replacement byte sequence, so distinct kinds would share one anchor. Fail closed instead; the
    caller has malformed text and needs to know.
    """
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as e:
        raise ValueError(
            "%s is not encodable as UTF-8 and MUST be rejected, not substituted (SPEC §4 E4): "
            "%s at position %d" % (what, e.reason, e.start)) from None


def inkan_seed(data: Union[str, bytes], kind: str = "") -> bytes:
    """Domain-separated Inkan glyph seed: ``INKAN_DOMAIN + u8(len(kind)) + kind + data``.

    The kind is **length-prefixed** so the kind/data boundary is unambiguous for EVERY possible
    kind string and payload (without it, ``generic(b"address\\0X")`` collided with ``address(b"X")``).
    ``len(kind_utf8)`` must be <= 255.

    **Unicode:** string inputs are NFC-normalised before UTF-8 encoding, so the same text typed two
    ways yields the same Inkan. Raw ``bytes`` data is used verbatim — it is not text and must not be
    normalised. Text holding a code point this interpreter's Unicode database leaves unassigned is
    rejected with ``ValueError`` before it is normalised (SPEC §1 E14); raw bytes are never checked.

    (The function name is retained for call-site compatibility with existing integrations.)
    """
    if isinstance(data, str):
        reject_unassigned(data, "data")
        data = _encode_utf8(_norm(data), "data")
    reject_unassigned(kind, "kind")
    kind_bytes = _encode_utf8(_norm(kind), "kind")
    if len(kind_bytes) > 255:
        raise ValueError("kind must be at most 255 UTF-8 bytes")
    return INKAN_DOMAIN + bytes([len(kind_bytes)]) + kind_bytes + data


def inkan_digest(data: Union[str, bytes], kind: str = "") -> bytes:
    """The raw 32-byte anchor: SHA-256 of the glyph seed. This is what the renderer consumes and
    what a receipt commits to; the code strings below are its self-identifying presentations."""
    import hashlib
    return hashlib.sha256(inkan_seed(data, kind)).digest()


def inkan_code(data: Union[str, bytes], kind: str = "", length: int = None) -> str:
    """The Inkan's **unique code**: ``ik1`` + hex SHA-256 of its glyph seed.

    ``length`` truncates the hex BODY (the ``ik1`` prefix is always kept). Full is the canonical
    anchor code; :data:`SHORT_CODE_LEN` gives the standard short form. The body is a genuine prefix
    of the digest, so any code is auditable by recomputing and checking. The code is a label only;
    trust decisions use the full digest or the seal itself."""
    hexd = inkan_digest(data, kind).hex()
    return CODE_PREFIX + (hexd if length is None else hexd[:length])


def inkan_short_code(data: Union[str, bytes], kind: str = "") -> str:
    """The standard SHORT code (``ik1`` + :data:`SHORT_CODE_LEN` hex) for filenames and display."""
    return inkan_code(data, kind, SHORT_CODE_LEN)


#: Length (hex chars) of the FULL code body: SHA-256, 32 bytes. SPEC §2 defines exactly two code
#: forms, ``ik1`` + 64 hex (full) and ``ik1`` + 16 hex (short); nothing else is a code.
FULL_CODE_LEN = 64

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def code_to_digest_hex(code: str) -> str:
    """Parse a **full** Inkan code (``ik1`` + 64 hex, SPEC §2) and return its anchor as lowercase hex.

    This function is the only implementation of §2's "a conforming reader MUST reject a code whose
    version it does not implement rather than assume SHA-256", so every way a code can be malformed
    has to end here, loudly. It previously checked the prefix and nothing else, which left four ways
    to get a wrong answer instead of an exception:

    * **No version digit.** The check was ``startswith("ik")`` then ``startswith("ik1")``, so a code
      written ``ik`` + digest passed whenever the digest happened to begin with ``1`` — one anchor in
      sixteen — and the caller silently received a 63-character body. The version has to be read
      *positionally*, not by prefix match against the rest of the string.
    * **Wrong body length.** A truncated or over-long body was returned verbatim.
    * **Non-hex body.** ``ik1`` + 64 ``z`` characters was returned as if it were a digest.
    * **A short code.** ``ik1`` + 16 hex is a legitimate SPEC §2 form, but it is a *label*: it does
      not carry the anchor. Returning its 16 hex characters from a function named for the digest
      invites exactly the truncated comparison §9 E8 forbids ("MUST NOT return a GENUINE verdict from
      any comparison shorter than the full 32-byte digest"). It is refused with a message that names
      it, because telling someone holding a valid short code "not an Inkan code" is a wrong diagnosis.

    The body is returned lowercased. ``inkan_code`` emits lowercase, so a caller comparing an
    uppercase code's body against a freshly computed digest would otherwise get a false MISMATCH —
    a wrong verdict from a presentation difference the spec does not distinguish.
    """
    if not isinstance(code, str):
        raise ValueError(f"an Inkan code is a string, got {type(code).__name__}")
    if code[:2] != "ik":
        raise ValueError(f"not an Inkan code: {code!r}")
    if code[:len(CODE_PREFIX)] != CODE_PREFIX:
        raise ValueError(f"unsupported code format {code[:len(CODE_PREFIX)]!r}; this build "
                         f"understands {CODE_PREFIX!r}. A code whose version this build does not "
                         f"implement MUST be rejected, never read as SHA-256 (SPEC §2)")
    body = code[len(CODE_PREFIX):]
    if not body:
        raise ValueError(f"{code!r} is a bare {CODE_PREFIX!r} prefix carrying no digest at all")
    if any(c not in _HEX_DIGITS for c in body):
        raise ValueError(f"Inkan code body is not hex: {body!r}")
    if len(body) == SHORT_CODE_LEN:
        raise ValueError(
            f"{code!r} is a SHORT code ({SHORT_CODE_LEN} hex): a filename/display label that carries "
            f"only a prefix of the anchor, not the anchor itself. Recompute and compare the full "
            f"{FULL_CODE_LEN}-hex digest — a verdict from a shorter comparison is forbidden (SPEC §9 E8)")
    if len(body) != FULL_CODE_LEN:
        raise ValueError(f"Inkan code body must be {FULL_CODE_LEN} hex characters (SHA-256), "
                         f"got {len(body)}: {code!r}")
    return body.lower()
